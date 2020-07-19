import os

DEBUG = False

BASE_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), '..')
DATABASE = 'sqlite:///' + os.path.join(BASE_DIR, 'osmcards.db')
BASE_URL = 'http://localhost:5000'
ADMINS = [1]

OAUTH_KEY = ''
OAUTH_SECRET = ''
SECRET_KEY = 'sdkdfsdf213fhsfljhsadf'

REPLY_TO = 'osmcrossing@localhost'
EMAIL_FROM = 'osmcrossing@localhost'
EMAIL_HOST = ''
EMAIL_PORT = 465
EMAIL_USE_SSL = True
EMAIL_USERNAME = ''
EMAIL_PASSWORD = ''
