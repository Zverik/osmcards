import click
from enum import IntEnum
from datetime import datetime
from flask.cli import with_appcontext, current_app
from playhouse.db_url import connect
from playhouse.migrate import (
    migrate as peewee_migrate,
    SqliteMigrator,
    MySQLMigrator,
    PostgresqlMigrator
)
from peewee import (
    fn,
    DatabaseProxy,
    Model,
    CharField,
    IntegerField,
    ForeignKeyField,
    BooleanField,
    DateTimeField
)

database = DatabaseProxy()


def set_up_logging():
    import logging
    logger = logging.getLogger('peewee')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)


def init_app(app):
    def open_db():
        database.connect()

    def close_db(exception):
        if not database.is_closed():
            database.close()

    new_db = connect(app.config['DATABASE'])
    database.initialize(new_db)
    app.before_request(open_db)
    app.teardown_request(close_db)


def fn_Random():
    if 'mysql' in current_app.config['DATABASE']:
        return fn.Rand()
    else:
        return fn.Random()


class AddressPrivacy(IntEnum):
    OPEN = 2  # Any user can get this user's data
    CONFIRMED = 4  # Visible to only confirmed users
    PROFILE = 6  # Does not participate in random
    ASK = 8  # Ask for permission, not in random
    CLOSED = 10  # Does not appear anywhere


class BaseModel(Model):
    class Meta:
        database = database


class User(BaseModel):
    created_on = DateTimeField(default=datetime.now)
    active_on = DateTimeField(default=datetime.now)
    name = CharField(max_length=250)
    code = IntegerField(index=True)  # Secret code to request a postcard
    osm_uid = IntegerField(index=True)
    osm_name = CharField()
    email = CharField(max_length=250, null=True)
    description = CharField(null=True)  # "About", like on postcrossing. No links.
    languages = CharField(default='English')  # Plain text
    site_lang = CharField(max_length=7, default='en')
    address = CharField(null=True)  # Properly formatted, with newlines
    is_active = BooleanField(default=True)  # False if not visible. Kind of account deletion
    privacy = IntegerField(default=AddressPrivacy.OPEN)
    does_requests = BooleanField(default=False)
    country = CharField(max_length=250, null=True)  # TODO: free-form or string name?

    @property
    def is_registered(self):
        return self.name and self.address and self.is_active


class MailCode(BaseModel):
    created_on = DateTimeField(default=datetime.now)
    code = IntegerField(primary_key=True)
    sent_by = ForeignKeyField(User, index=True)
    sent_to = ForeignKeyField(User)
    sent_address = CharField()
    sent_on = DateTimeField(null=True)
    received_on = DateTimeField(null=True)
    comment = CharField(null=True)  # Comment from receiver
    is_active = BooleanField(default=True)  # Not received and not expired


class MailRequest(BaseModel):
    created_on = DateTimeField(default=datetime.now)
    is_active = BooleanField(default=True)
    is_hidden = BooleanField(default=False)
    requested_by = ForeignKeyField(User, index=True)
    requested_from = ForeignKeyField(User, index=True)
    comment = CharField(null=True)


# MIGRATION #############################################


LAST_VERSION = 0


class Version(BaseModel):
    version = IntegerField()


@click.command('migrate')
@with_appcontext
def migrate():
    database.connect()
    database.create_tables([Version], safe=True)
    try:
        v = Version.select().get()
    except Version.DoesNotExist:
        print('Creating tables')
        database.create_tables([User, MailCode, MailRequest])
        v = Version(version=LAST_VERSION)
        v.save()

    if v.version >= LAST_VERSION:
        return

    print('Upgrading database version {} to version {}'.format(v.version, LAST_VERSION))

    uri = current_app.config['DATABASE']
    if 'mysql' in uri:
        migrator = MySQLMigrator(database)
    elif 'sqlite' in uri:
        migrator = SqliteMigrator(database)
    else:
        migrator = PostgresqlMigrator(database)

    # TODO: write migrations here

    if v.version != LAST_VERSION:
        raise ValueError('LAST_VERSION in db.py should be {}'.format(v.version))
