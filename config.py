import hashlib
import hmac
import os
import redis
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session


class ApplicationConfig:

    redis_client = redis.Redis()

    SECRET_KEY = os.environ.get("SECRET_KEY")

    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get(
        "SQLALCHEMY_TRACK_MODIFICATIONS")
    SQLALCHEMY_ECHO = os.environ.get("SQLALCHEMY_ECHO")
    SQLALCHEMY_POOL_SIZE = 20
    SQLALCHEMY_POOL_TIMEOUT = 3000
    SQLALCHEMY_POOL_RECYCLE = 36000

    # SQLALCHEMY_DATABASE_URI = r"sqlite:///./db.sqlite"
    username = os.environ.get("USERNAME")
    password = os.environ.get("PASSWORD")
    localhost = os.environ.get("LOCALHOST")
    dbname = os.environ.get("DBNAME")
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:*dC-2aG*314A66ae1f3e6D64d-446B3G@viaduct.proxy.rlwy.net:30740/railway"

    DATABASE_ENGINE = create_engine(SQLALCHEMY_DATABASE_URI)
    SESSION_TYPE = os.environ.get("SESSION_TYPE")
    REDIS_URL = "redis://default:fdMgaPnGoOkK12ig5kckE44iDMjFOPKK@monorail.proxy.rlwy.net:33538"
    SESSION_REDIS = redis.from_url(REDIS_URL)
    SESSION_KEY_PREFIX = os.environ.get("SESSION_KEY_PREFIX")
    # SESSION_REDIS = redis_client
    SESSION_PERMANENT = os.environ.get("SESSION_PERMANENT")
    SESSION_USE_SIGNER = os.environ.get("SESSION_USE_SIGNER")
    PERMANENT_SESSION_LIFETIME = 86400

    MAIL_SERVER = 'smtp.elasticemail.com'
    MAIL_PORT = 2525
    MAIL_USERNAME = 'support@enetworksagencybanking.com.ng'
    MAIL_PASSWORD = "A2CDE2AB8EEE085BBF14DFF4D75315C7BF75"
    MAIL_USE_TLS = True

    DATABASE_INITIALIZED = False

    JWT_ACCESS_TOKEN_EXPIRES = 43200
