from . import flask_lang
from .db import User, MailCode, MailRequest, AddressPrivacy, fn_Random
from authlib.integrations.flask_client import OAuth
from authlib.common.errors import AuthlibBaseError
from xml.etree import ElementTree as etree
from random import randrange, choices
import os
from flask import (
    Blueprint, session, url_for, redirect, request,
    render_template, g, flash
)
from peewee import JOIN
from flask_wtf import FlaskForm
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


@cross.before_request
def before_request():
    g.user = get_user()
    lang = None if not g.user else g.user.site_lang
    flask_lang.load_language(lang)


@cross.app_template_global()
def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(cross.root_path,
                                     endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)


@cross.app_context_processor
def inject_lang():
    return dict(lang=g.lang)


def generate_user_code():
    letters = 'abcdefghijklmnopqrstuvwxyz123456789'
    return ''.join(choices(letters, k=8))


@cross.route('/login')
def login():
    redirect_uri = url_for('c.auth', _external=True)
    return oauth.openstreetmap.authorize_redirect(redirect_uri)


@cross.route('/auth')
def auth():
    client = oauth.openstreetmap
    try:
        client.authorize_access_token()
    except AuthlibBaseError:
        return 'Denied. <a href="' + url_for('c.login') + '">Try again</a>.'

    response = client.get('user/details')
    user_details = etree.fromstring(response.content)
    uid = int(user_details[0].get('id'))
    name = user_details[0].get('display_name')

    user = User.get_or_none(osm_uid=uid)
    if not user:
        # No such user, let's create one
        lang = flask_lang.get_language_from_request()
        user = User.create(name='', site_lang=lang, osm_uid=uid,
                           osm_name=name, code=generate_user_code())
        flash('Welcome! Please fill in your name and address to start '
              'sending and receiving postcards.', 'info')
    else:
        if user.osm_name != name:
            user.osm_name = name
            user.save()

    session['uid'] = user.id
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
    requests = MailRequest.select().where(
        MailRequest.requested_from == g.user,
        MailRequest.is_hidden == False,
        MailRequest.is_active == True
    ).order_by(MailRequest.created_on)

    return render_template(
        'front.html', mailcodes=mailcodes, sent_cards=sent_cards,
        requests=requests)


class UserForm(FlaskForm):
    name = StringField(
        'Your name',
        description='Usually the real one, or whatever you prefer — for postcards and the profile',
        validators=[validators.DataRequired(), validators.Length(min=2)]
    )
    email = StringField(
        'Email',
        description='We won\'t send you anything besides notifications',
        validators=[validators.Optional(), validators.Regexp(r'^[^@]+@.+\.\w+$')])

    description = TextAreaField('Write some words about yourself and what you like')
    country = StringField('Country', validators=[validators.Optional()])
    # country = SelectField(
    #     'Country',
    #     description='Please excuse me for not using autocomplete yet',
    #     choices=[('', '<please select>'), ('BY', 'Belarus'), ('RU', 'Russian Federation')],
    #     validators=[validators.DataRequired()]
    # )
    address = TextAreaField(
        'Your postal address, in latin letters',
        validators=[validators.DataRequired()]
    )
    languages = StringField('Languages you can read, comma-separated')
    does_requests = BooleanField('I send postcards on request')
    privacy = RadioField(
        'Who sees my address',
        choices=[
            (2, 'Anybody at random'),
            (4, 'Confirmed users at random and profile visitors'),
            (6, 'Profile visitors only'),
            (8, 'Profile visitors, only after I accept (doesn\'t work for now)'),
            (10, 'Nobody'),
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
            flash('There are some errors, please fix them.')
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
            flash('Profile has been updated.', 'info')
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
def send():
    if not g.user:
        return redirect(url_for('c.front'))
    try:
        find_user_to_send()
    except User.DoesNotExist:
        flash('No users without your postcards left, sorry.')
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


@cross.route('/dosend')
def dosend():
    if not g.user:
        return redirect(url_for('c.front'))
    code = generate_mail_code()
    if not code:
        flash('Failed to generate a mail code.')
        return redirect(url_for('c.front'))

    user_code = request.args.get('user')
    if user_code:
        user = User.get_or_none(User.code == user_code)
        if not user:
            flash('There is no user with this private code.')
            return redirect(url_for('c.front'))
        lastcode = MailCode.get_or_none(
            MailCode.sent_by == g.user,
            MailCode.sent_to == user,
            MailCode.is_active == True
        )
        if lastcode:
            flash('You are already sending them a postcard.')
            return redirect(url_for('c.profile', pcode=user_code))
    else:
        user = find_user_to_send()
    MailCode.create(code=code, sent_by=g.user, sent_to=user, sent_address=user.address)
    return redirect(url_for('c.profile', scode=code))


@cross.route('/request/<code>')
def req(code):
    if not g.user:
        return redirect(url_for('c.front'))
    user = User.get_or_none(User.code == code)
    if not user:
        flash('There is no user with this private code.')
        return redirect(url_for('c.front'))

    old_req = MailRequest.get_or_none(
        MailRequest.requested_by == g.user,
        MailRequest.requested_from == user,
        MailRequest.is_active == True
    )
    if old_req:
        flash('Sorry, you have already made a request.')
        return redirect(url_for('c.profile', pcode=code))
    MailRequest.create(
        requested_by=g.user, requested_from=user,
        comment='Hey, please send me a postcard!'
    )
    return redirect(url_for('c.profile', pcode=code))


@cross.route('/profile')
@cross.route('/profile/<pcode>')
@cross.route('/send/<scode>')
def profile(pcode=None, scode=None):
    mailcode = None
    if pcode:
        puser = User.get_or_none(User.code == pcode)
        if not puser or not puser.is_registered:
            flash('There is no user with this private code.')
            return redirect(url_for('c.front'))
    elif scode:
        mailcode = MailCode.get_or_none(MailCode.code == scode)
        if not mailcode or mailcode.sent_by != g.user:
            flash('No such mailcode.')
            return redirect(url_for('c.front'))
        puser = mailcode.sent_to
    else:
        puser = g.user
    if not puser:
        # Should not happen
        return 'Sorry, no user with this code'

    request = recent_postcard = None
    can_send = can_request = recently_registered = False
    is_me = g.user == puser
    if not is_me:
        request = MailRequest.get_or_none(
            MailRequest.requested_by == g.user,
            MailRequest.requested_from == puser,
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
        can_send = not mailcode and puser.privacy <= AddressPrivacy.PROFILE
        can_request = not scode and puser.does_requests and not recent_postcard
    return render_template(
        'profile.html', user=puser, me=is_me, code=mailcode, req=request,
        from_mailcode=scode is not None, can_send=can_send,
        can_request=can_request,
        recent_card=None if not recently_registered else recent_postcard)


@cross.route('/togglesent/<code>')
def togglesent(code):
    if not g.user:
        return redirect(url_for('c.front'))
    mailcode = MailCode.get_or_none(MailCode.code == code)
    if not mailcode or mailcode.sent_by != g.user:
        flash('No such mailcode.')
        return redirect(url_for('c.front'))
    if mailcode.sent_on:
        mailcode.sent_on = None
    else:
        mailcode.sent_on = datetime.now()
    mailcode.save()
    return redirect(url_for('c.profile', scode=code))


@cross.route('/register')
def register():
    if not g.user:
        return redirect(url_for('c.front'))
    code = request.args.get('code')
    if not code:
        return render_template('register.html', code=None)
    mailcode = MailCode.get_or_none(
        MailCode.code == code,
        MailCode.sent_to == g.user,
    )
    if not mailcode:
        flash('Cannot find a postcard with this code. Please try again.')
        return render_template('register.html', code=code)

    pcode = mailcode.sent_by.code
    if not mailcode.is_active:
        flash('This postcard has already been registered. Thank you!', 'info')
        if mailcode.received_on and mailcode.sent_by.privacy < AddressPrivacy.CLOSED:
            is_recent = (datetime.now() - mailcode.received_on).total_seconds() < 3600 * 24
            if is_recent:
                return redirect(url_for('c.profile', pcode=pcode))
        return redirect(url_for('c.front'))

    mailcode.received_on = datetime.now()
    mailcode.is_active = False
    mailcode.save()
    flash('Thank you for registering the postcard! '
          'Write a message to the user if you like.', 'info')
    if mailcode.sent_by.privacy < AddressPrivacy.CLOSED:
        return redirect(url_for('c.profile', pcode=pcode))
    return redirect(url_for('c.front'))


@cross.route('/comment/<code>', methods=['POST'])
def comment(code):
    if not g.user:
        return redirect(url_for('c.front'))
    mailcode = MailCode.get_or_none(
        MailCode.code == code,
        MailCode.sent_to == g.user
    )
    if not mailcode:
        flash('Cannot find a postcard with this code. Please try again.')
        return redirect(url_for('c.front'))
    comment = request.form.get('comment', '').strip()
    if comment:
        if mailcode.comment:
            flash('Cannot change already stored comment, sorry.')
        else:
            mailcode.comment = comment
            mailcode.save()
            flash('Comment sent, thank you for connecting!', 'info')
    return redirect(url_for('c.profile', pcode=mailcode.sent_by.code))


@cross.route('/set-lang', methods=['POST'])
def set_lang():
    user = g.user
    if not user:
        return redirect(url_for('c.front'))
    new_lang = request.form['lang']
    if new_lang != user.lang and new_lang in flask_lang.get_supported_languages():
        user.lang = new_lang
        user.save()
    return redirect(request.form.get('redirect', url_for('c.user')))
