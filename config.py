# coding: utf8

# SMTP_HOST = 'smtpdm.aliyun.com'
# SMTP_PORT = 80
# SMTP_SENDER = 'sender@mail.gakki.tech'
# SMTP_LOGIN = 'sender@mail.gakki.tech'
# SMTP_PASSWORD = 'ZSsdlh12345'
#
# ETH_ENCRYPT_PASSWORD = '123456'
# BLOCKLINK_ERC20_CONTRACT_ADDRESS = ''  # FIXME

import os
from celery.schedules import crontab
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    FLASKY_MAIL_SUBJECT_PREFIX = ''
    FLASKY_MAIL_SENDER = ''
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN')

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SMTP_HOST = 'smtpdm.aliyun.com'
    SMTP_PORT = 80
    SMTP_SENDER = 'sender@mail.gakki.tech'
    SMTP_LOGIN = 'sender@mail.gakki.tech'
    SMTP_PASSWORD = 'ZSsdlh12345'

    ETH_ENCRYPT_PASSWORD = '123456'
    BLOCKLINK_ERC20_CONTRACT_ADDRESS = ''  # FIXME
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'dev.db')

    SQLALCHEMY_TRACK_MODIFICATIONS = True
    # SQLALCHEMY_POOL_SIZE = 200

    NEED_CAPTCHA = False

    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
    CELERY_TIMEZONE = 'Asia/Shanghai'  # set timezone in here
    CELERYBEAT_SCHEDULE = {
        'every-one-minute': {
            'task': 'crawl_eth_token_deposit',
            'schedule': crontab(minute="*/1")
        },
    }


class TestingConfig(Config):
    DEBUG = True
    SMTP_HOST = 'smtpdm.aliyun.com'
    SMTP_PORT = 80
    SMTP_SENDER = 'sender@mail.gakki.tech'
    SMTP_LOGIN = 'sender@mail.gakki.tech'
    SMTP_PASSWORD = 'ZSsdlh12345'

    ETH_ENCRYPT_PASSWORD = '123456'
    BLOCKLINK_ERC20_CONTRACT_ADDRESS = ''  # FIXME
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'test.db')

    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_POOL_SIZE = 200

    NEED_CAPTCHA = False

    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
    CELERY_TIMEZONE = 'Asia/Shanghai'  # set timezone in here
    CELERYBEAT_SCHEDULE = {
        'every-one-minute': {
            'task': 'crawl_eth_token_deposit',
            'schedule': crontab(minute="*/1")
        },
    }


class ProductionConfig(Config):
    SMTP_HOST = 'smtpdm.aliyun.com'
    SMTP_PORT = 80
    SMTP_SENDER = 'sender@mail.gakki.tech'
    SMTP_LOGIN = 'sender@mail.gakki.tech'
    SMTP_PASSWORD = 'ZSsdlh12345'

    ETH_ENCRYPT_PASSWORD = '12345ssdlh'
    BLOCKLINK_ERC20_CONTRACT_ADDRESS = ''  # FIXME
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'production.db')  # FIXME

    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_POOL_SIZE = 200

    NEED_CAPTCHA = True

    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
    CELERY_TIMEZONE = 'Asia/Shanghai'  # set timezone in here
    CELERYBEAT_SCHEDULE = {
        'every-one-minute': {
            'task': 'crawl_eth_token_deposit',
            'schedule': crontab(minute="*/1")
        },
    }


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
