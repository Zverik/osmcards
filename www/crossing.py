from .db import User, MailCode, MailRequest, AddressPrivacy, fn_Random
from .mail import mail, Message
from authlib.integrations.flask_client import OAuth
from authlib.common.errors import AuthlibBaseError
from xml.etree import ElementTree as etree
from random import randrange, choices
import os
from flask import (
    Blueprint, session, url_for, redirect, request,
    render_template, g, flash, current_app
)
from functools import wraps
from peewee import JOIN
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError
from flask_babel import _, lazy_gettext as _l, format_date, force_locale
from datetime import datetime, timedelta
from wtforms import (
    validators, StringField, TextAreaField,
    BooleanField, RadioField
)


oauth = OAuth()
oauth.register(
    name='openstreetmap',
    api_base_url='https://api.openstreetmap.org/api/0.6/',
    request_token_url='https://www.openstreetmap.org/oauth/request_token',
    access_token_url='https://www.openstreetmap.org/oauth/access_token',
    authorize_url='https://www.openstreetmap.org/oauth/authorize'
)

cross = Blueprint('c', __name__)


def get_user():
    if session.get('uid'):
        user = User.get_or_none(session['uid'])
        if user:
            # Update active date
            now = datetime.now()
            if (user.active_on - now).total_seconds() > 3600:
                user.active_on = now
                user.save()
            # Check if the user is confirmed: 1 sent and 1 received
            count1 = MailCode.select(MailCode.code).where(
                MailCode.sent_by == user,
                MailCode.received_on.is_null(False)
            ).limit(1).count()
            count2 = MailCode.select(MailCode.code).where(
                MailCode.sent_to == user,
                MailCode.received_on.is_null(False)
            ).limit(1).count()
            user.is_confirmed = count1 + count2 >= 2
            return user
    return None


def login_requred(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user:
            return redirect(url_for('c.login', next=request.url))
        if not g.user.is_registered:
            return redirect(url_for('c.user'))
        return f(*args, **kwargs)
    return decorated_function


@cross.before_request
def before_request():
    g.user = get_user()
    # TODO: set site language


@cross.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash(_('The CSRF token is invalid. Try again maybe.'))
    return redirect(url_for('c.front'))


@cross.app_template_global()
def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(cross.root_path,
                                     endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)


@cross.app_template_global()
def my_format_date(date):
    if date.year == datetime.now().year:
        return format_date(date, 'd MMMM')
    return format_date(date, 'd MMM yyyy')


def send_email(user, subject, body):
    if not user.email or '@' not in user.email:
        return False
    if not current_app.config['MAIL_SERVER']:
        return False

    header = _('Hi %(name)s,', name=user.name)
    footer = 'OSM Cards'
    msg = Message(
        subject=subject,
        body=f'{header}\n\n{body}\n\n{footer}',
        from_email=('OSM Cards', current_app.config['MAIL_FROM']),
        to=[f'{user.name} <{user.email}>'],
        reply_to=[current_app.config['REPLY_TO']]
    )
    try:
        mail.send(msg)
    except OSError as e:
        current_app.logger.exception(e)
        flash(_('Other user was not notified: %(error)s', error=e))
        return False
    return True


def generate_user_code():
    letters = 'abcdefghijklmnopqrstuvwxyz123456789'
    return ''.join(choices(letters, k=8))


@cross.route('/login')
def login():
    if request.args.get('next'):
        session['next'] = request.args['next']
    redirect_uri = url_for('c.auth', _external=True)
    return oauth.openstreetmap.authorize_redirect(redirect_uri)


@cross.route('/auth')
def auth():
    client = oauth.openstreetmap
    try:
        client.authorize_access_token()
    except AuthlibBaseError:
        return _('Authorization denied. <a href="%s">Try again</a>.', url_for('c.login'))

    response = client.get('user/details')
    user_details = etree.fromstring(response.content)
    uid = int(user_details[0].get('id'))
    name = user_details[0].get('display_name')

    user = User.get_or_none(osm_uid=uid)
    if not user:
        # No such user, let's create one
        # TODO: proper identifying of languages
        lang = request.accept_languages.best_match(['en', 'ru'])
        user = User.create(name='', site_lang=lang, osm_uid=uid,
                           osm_name=name, code=generate_user_code())
        flash(_('Welcome! Please fill in your name and address to start '
                'sending and receiving postcards.'), 'info')
    else:
        if user.osm_name != name:
            user.osm_name = name
            user.save()

    session['uid'] = user.id
    session.permanent = True
    if not user.is_registered:
        return redirect(url_for('c.user'))

    if session.get('next'):
        redir = session['next']
        del session['next']
    else:
        redir = url_for('c.front')
    return redirect(redir)


@cross.route('/logout')
def logout():
    if 'uid' in session:
        del session['uid']
    return redirect(url_for('c.front'))


@cross.route('/')
def front():
    if not g.user:
        return render_template('index.html')
    if not g.user.is_registered:
        return redirect(url_for('c.user', first=1))

    mailcodes = MailCode.select().where(
        MailCode.sent_by == g.user,
        MailCode.is_active == True,
        MailCode.sent_on.is_null(True)
    ).order_by(MailCode.created_on.desc())
    sent_cards = MailCode.select().where(
        MailCode.sent_by == g.user,
        MailCode.is_active == True,
        MailCode.sent_on.is_null(False)
    ).order_by(MailCode.sent_on.desc())
    delivered_cards = MailCode.select().where(
        (MailCode.sent_by == g.user | MailCode.sent_to == g.user),
        MailCode.received_on.is_null(False)
    ).order_by(MailCode.received_on.desc()).limit(10)
    requests = MailRequest.select().where(
        MailRequest.requested_from == g.user,
        MailRequest.is_hidden == False,
        MailRequest.is_active == True
    ).order_by(MailRequest.created_on)

    return render_template(
        'front.html', mailcodes=mailcodes, sent_cards=sent_cards,
        requests=requests, delivered_cards=delivered_cards)


class UserForm(FlaskForm):
    name = StringField(
        _l('Your name'),
        description=_l('Usually the real one, or whatever you prefer — '
                       'for postcards and the profile'),
        validators=[validators.DataRequired(), validators.Length(min=2)]
    )
    email = StringField(
        _l('Email'),
        description=_l('We won\'t send you anything besides notifications'),
        validators=[validators.Optional(), validators.Regexp(r'^[^@]+@.+\.\w+$')])

    description = TextAreaField(_l('Write some words about yourself and what you like'))
    country = StringField(_l('Country'), validators=[validators.Optional()])
    # country = SelectField(
    #     'Country',
    #     description='Please excuse me for not using autocomplete yet',
    #     choices=[('', '<please select>'), ('BY', 'Belarus'), ('RU', 'Russian Federation')],
    #     validators=[validators.DataRequired()]
    # )
    address = TextAreaField(
        _l('Your postal address, in latin letters'),
        validators=[validators.DataRequired()]
    )
    languages = StringField(_l('Languages you can read, comma-separated'))
    does_requests = BooleanField(_l('I send postcards on request'))
    privacy = RadioField(
        _l('Who sees my address'),
        choices=[
            (2, _l('Anybody at random')),
            (4, _l('Confirmed users at random and profile visitors')),
            (6, _l('Profile visitors only')),
            (8, _l('Profile visitors, only after I accept')),
            (10, _l('Nobody')),
        ],
        coerce=int
    )


@cross.route('/user', methods=('GET', 'POST'))
def user():
    if not g.user:
        return redirect(url_for('c.front'))
    user = get_user()
    form = UserForm(obj=user)
    if form.is_submitted():
        if not form.validate():
            flash(_('There are some errors, please fix them.'))
            for field in form:
                if field.errors:
                    print(field, field.errors)
        else:
            form.populate_obj(user)
            for k in ('country', 'email', 'description', 'address'):
                v = getattr(form, k).data
                if v is None or not v.strip():
                    setattr(user, k, None)
            user.save()
            flash(_('Profile has been updated.'), 'info')
            return redirect(url_for('c.user'))

    MailCodeAlias = MailCode.alias()
    count_confirmed = (
        User.select()
        .join_from(User, MailCode, on=(
            (MailCode.sent_by == User.id) & (MailCode.received_on.is_null(False))
        ))
        .join_from(User, MailCodeAlias, on=(
            (MailCodeAlias.sent_to == User.id) & (MailCodeAlias.received_on.is_null(False))
        )).where(User.is_active == True).count()
    )
    return render_template('settings.html', form=form, count_confirmed=count_confirmed)


def find_user_to_send():
    max_privacy = AddressPrivacy.CONFIRMED if g.user.is_confirmed else AddressPrivacy.OPEN
    q = User.select().join(MailCode, on=(
        (MailCode.sent_by == g.user) & (MailCode.sent_to == User.id) &
        ((MailCode.is_active == True) | MailCode.received_on.is_null(True))
    ), join_type=JOIN.LEFT_OUTER).where(
        User.id != g.user.id,
        User.is_active == True,
        User.name.is_null(False),
        User.name != '',
        User.address.is_null(False),
        User.address != '',
        User.privacy <= max_privacy,
        MailCode.code.is_null(True),
    ).order_by(fn_Random())
    return q.get()


@cross.route('/send')
@login_requred
def send():
    max_cards = 4 if not g.user.is_confirmed else 8
    has_cards = MailCode.select().where(
        MailCode.sent_by == g.user,
        MailCode.is_active == True
    ).count()
    if has_cards >= max_cards:
        flash(_('You have got too many cards travelling, '
                'please wait until some of these are delivered.'))
        return redirect(url_for('c.front'))

    try:
        find_user_to_send()
    except User.DoesNotExist:
        flash(_('No users without your postcards left, sorry.'))
        return redirect(url_for('c.front'))
    return render_template('send.html')


def generate_mail_code():
    try:
        tries = 10
        while tries > 0:
            code = randrange(1e4, 1e5)
            MailCode.get_by_id(code)
            tries -= 1
        return None
    except MailCode.DoesNotExist:
        return code


@cross.route('/dosend', methods=['POST'])
@login_requred
def dosend():
    code = generate_mail_code()
    if not code:
        flash(_('Failed to generate a mail code.'))
        return redirect(url_for('c.front'))

    user_code = request.form.get('user')
    if user_code:
        user = User.get_or_none(User.code == user_code)
        if not user:
            flash(_('There is no user with this private code.'))
            return redirect(url_for('c.front'))
        lastcode = MailCode.get_or_none(
            MailCode.sent_by == g.user,
            MailCode.sent_to == user,
            MailCode.is_active == True
        )
        if lastcode:
            flash(_('You are already sending them a postcard.'))
            return redirect(url_for('c.profile', pcode=user_code))
    else:
        user = find_user_to_send()
    MailCode.create(code=code, sent_by=g.user, sent_to=user, sent_address=user.address)

    # Clear postcard requests
    they_requested = MailRequest.get_or_none(
        MailRequest.requested_by == user,
        MailRequest.requested_from == g.user,
        MailRequest.is_active == True
    )
    if they_requested:
        they_requested.is_active = False
        they_requested.save()

    return redirect(url_for('c.profile', scode=code))


@cross.route('/request', methods=['POST'])
@login_requred
def req():
    code = request.form.get('user')
    user = User.get_or_none(User.code == code)
    if not user:
        flash(_('There is no user with this private code.'))
        return redirect(url_for('c.front'))

    old_req = MailRequest.get_or_none(
        MailRequest.requested_by == g.user,
        MailRequest.requested_from == user,
        MailRequest.is_active == True
    )
    if old_req:
        flash(_('Sorry, you have already made a request.'))
        return redirect(url_for('c.profile', pcode=code))
    MailRequest.create(
        requested_by=g.user, requested_from=user,
        comment='Hey, please send me a postcard!'
    )
    with force_locale(user.site_lang or 'en'):
        send_email(user, _('Please send a postcard'), '{}\n\n{}'.format(
            _('%(user)s has asked you to send them a postcard. '
              'Please click on the button in their profile and send one!',
              user=g.user.name),
            url_for('c.profile', pcode=g.user.code, _external=True))
        )
    return redirect(url_for('c.profile', pcode=code))


@cross.route('/profile')
@cross.route('/profile/<pcode>')
@cross.route('/send/<scode>')
@login_requred
def profile(pcode=None, scode=None):
    mailcode = None
    if pcode:
        puser = User.get_or_none(User.code == pcode)
        if not puser or not puser.is_registered:
            flash(_('There is no user with this private code.'))
            return redirect(url_for('c.front'))
    elif scode:
        mailcode = MailCode.get_or_none(MailCode.code == scode)
        if not mailcode or mailcode.sent_by != g.user:
            flash(_('No such mailcode.'))
            return redirect(url_for('c.front'))
        if mailcode.received_on:
            return redirect(url_for('c.card', code=mailcode.code))
        puser = mailcode.sent_to
    else:
        puser = g.user
    if not puser:
        # Should not happen
        return _('Sorry, no user with this code.')

    prequest = recent_postcard = they_requested = None
    can_send = can_request = recently_registered = False
    is_me = g.user == puser
    if not is_me:
        prequest = MailRequest.get_or_none(
            MailRequest.requested_by == g.user,
            MailRequest.requested_from == puser,
            MailRequest.is_active == True
        )
        they_requested = MailRequest.get_or_none(
            MailRequest.requested_by == puser,
            MailRequest.requested_from == g.user,
            MailRequest.is_active == True
        )
        if not mailcode:
            mailcode = MailCode.get_or_none(
                MailCode.sent_by == g.user,
                MailCode.sent_to == puser,
                MailCode.is_active == True
            )
        try:
            recent_postcard = MailCode.select().where(
                MailCode.sent_by == puser,
                MailCode.sent_to == g.user,
                MailCode.received_on.is_null(False)
            ).order_by(MailCode.received_on.desc()).get()
        except MailCode.DoesNotExist:
            pass
        recently_registered = (
            recent_postcard and
            recent_postcard.received_on >= datetime.now() - timedelta(days=1)
        )
        # TODO: ask
        can_send = not mailcode and (they_requested or puser.privacy <= AddressPrivacy.PROFILE)
        can_request = (not scode and not they_requested and puser.does_requests and
                       not recent_postcard)
    return render_template(
        'profile.html', user=puser, me=is_me, code=mailcode, req=prequest,
        from_mailcode=scode is not None, can_send=can_send,
        can_request=can_request, they_requested=they_requested,
        recent_card=None if not recently_registered else recent_postcard)


@cross.route('/togglesent/<code>')
@login_requred
def togglesent(code):
    mailcode = MailCode.get_or_none(MailCode.code == code)
    if not mailcode or mailcode.sent_by != g.user:
        flash(_('No such mailcode.'))
        return redirect(url_for('c.front'))
    if mailcode.sent_on:
        mailcode.sent_on = None
    else:
        mailcode.sent_on = datetime.now()
    mailcode.save()
    return redirect(url_for('c.profile', scode=code))


@cross.route('/card/<code>')
@login_requred
def card(code):
    mailcode = MailCode.get_or_none(
        MailCode.code == code,
        # (MailCode.sent_by == g.user | MailCode.sent_to == g.user)
    )
    if not mailcode:
        flash(_('Cannot find a postcard with this code. Please check it again.'))
        return redirect(url_for('c.front'))
    if not mailcode.received_on:
        if mailcode.sent_by == g.user:
            # If the card was not received, show the user profile
            return redirect(url_for('c.profile', scode=mailcode.code))
        else:
            # User should not know the code before they've received the card.
            # Let's nudge them towards the registering page.
            return redirect(url_for('c.register'))
    other_user = mailcode.sent_by if mailcode.sent_to == g.user else mailcode.sent_to
    return render_template(
        'card.html', code=mailcode, from_me=mailcode.sent_by == g.user,
        other_user=other_user,
        can_see_profile=other_user.privacy < AddressPrivacy.CLOSED)


@cross.route('/register', methods=['GET', 'POST'])
@login_requred
def register():
    code = request.form.get('code')
    if not code:
        return render_template('register.html', code=None)
    mailcode = MailCode.get_or_none(
        MailCode.code == MailCode.restore_code(code),
        MailCode.sent_to == g.user,
    )
    if not mailcode:
        flash(_('Cannot find a postcard with this code. Please check it again.'))
        return render_template('register.html', code=code)

    if not mailcode.is_active:
        flash(_('This postcard has already been registered. Thank you!'), 'info')
        return redirect(url_for('c.card', code=mailcode.code))

    mailcode.received_on = datetime.now()
    mailcode.is_active = False
    mailcode.save()

    with force_locale(mailcode.sent_by.site_lang or 'en'):
        send_email(mailcode.sent_by, _('Your postcard %(code)s has arrived', code=mailcode.lcode),
                   '{}\n\n{}'.format(
            _('Your postcard to %(user) has arrived and has been registered '
              'just now, %(days) after sending!', user=g.user.name),
            url_for('c.card', code=mailcode.code, _external=True))
        )

    flash(_('Thank you for registering the postcard! '
            'Write a message to the user if you like.'), 'info')
    return redirect(url_for('c.card', code=mailcode.code))


@cross.route('/comment/<code>', methods=['POST'])
@login_requred
def comment(code):
    mailcode = MailCode.get_or_none(
        MailCode.code == code,
        MailCode.received_on.is_null(False),
        MailCode.sent_to == g.user
    )
    if not mailcode:
        flash(_('No such mailcode.'))
        return redirect(url_for('c.front'))
    comment = request.form.get('comment', '').strip()
    if comment:
        if mailcode.comment:
            flash(_('Cannot change already stored comment, sorry.'))
        else:
            mailcode.comment = comment
            mailcode.save()
            with force_locale(mailcode.sent_by.site_lang or 'en'):
                send_email(
                    mailcode.sent_by,
                    _('Comment on your postcard %(code)s', code=mailcode.lcode),
                    '{}:\n\n{}\n\n{}'.format(
                        _('%(user)s has just left a reply to your postcard', user=g.user.name),
                        comment, url_for('c.card', code=mailcode.code, _external=True))
                )
            flash(_('Comment sent, thank you for connecting!'), 'info')
    return redirect(url_for('c.card', code=mailcode.code))


@cross.route('/set-lang', methods=['POST'])
@login_requred
def set_lang():
    user = g.user
    if not user:
        return redirect(url_for('c.front'))
    new_lang = request.form['lang']
    # Proper list of languages
    if new_lang != user.lang and new_lang in ['en', 'ru']:
        user.lang = new_lang
        user.save()
    return redirect(request.form.get('redirect', url_for('c.user')))
