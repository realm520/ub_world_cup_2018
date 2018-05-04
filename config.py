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

ALLOWED_CROSS_ORIGIN_HEADERS = "Referer,Accept,Origin,User-Agent,Content-Type,X-TOKEN"


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or b'\x97d\x08\x9f\xa9Lj\x9bke\xf9\xdc.\xc3B8\xae\xc3\x196\xb4gvR'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    FLASKY_MAIL_SUBJECT_PREFIX = ''
    FLASKY_MAIL_SENDER = ''
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN')
    REDIS_URL = "redis://:@%s:6379/0" % os.getenv('RHOST', 'localhost')
    CELERY_TIMEZONE = 'Asia/Shanghai'  # set timezone in here

    SWEEP_TO_ETH_ADDRESS = None  # 归账目标地址
    SWEEP_GAS_SPENDER_ETH_ADDRESS = None  # 归账时需要从这个地址转一点ETH到以太充值地址作gas
    SWEEP_GAS_SPENDER_ETH_PRIVATE_KEY = None  # 归账时支付gas的以太地址的私钥

    GETH_RPC_URL = 'http://192.168.1.124:40018'

    MIN_SWEEP_BLOCKLINK_TOKEN_AMOUNT = (1**18)  # 以太充值账户中最少多少个blocklink 的ETH ERC20 token代币才进行归账操作

    CELERYBEAT_SCHEDULE = {
        'every-one-minute': {
            'task': 'crawl_eth_token_deposits',
            'schedule': crontab(minute="*/1"),
        },
        'sweep_deposit_eth_accounts_balances': {
            'task': 'sweep_deposit_eth_accounts_balances',
            'schedule': crontab(minute="*/10"),
        }
    }

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
    BLOCKLINK_ERC20_CONTRACT_ADDRESS = '0xd7cddd45629934c2f6ed3b63217bd8085d7c14a8'  # FIXME: this is AVH address for development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
                              "mysql+pymysql://root:123456@192.168.1.128:3306/blocklinkbackend_dev"

    SWEEP_TO_ETH_ADDRESS = '0xb4e71a0F74a09dDf76c47234d31111DAcbe320D2'
    SWEEP_GAS_SPENDER_ETH_ADDRESS = '0xD7794474db278d458BF7142D684D2849cE93e6B4'  # 归账时需要从这个地址转一点ETH到以太充值地址作gas
    SWEEP_GAS_SPENDER_ETH_PRIVATE_KEY = '0x0834c575daedb146ac310243ad983e0bc0b3603dbd2baed30af1977a1d058c4f'  # 归账时支付gas的以太地址的私钥

    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_POOL_SIZE = 200

    NEED_CAPTCHA = True

    ETHERSCAN_API_KEY = 'QQGM9I82DH2H9M7J8J21FHADIFBIDFQHWE'

    CELERY_BROKER_URL = 'redis://%s:6379/0' % os.getenv('RHOST', 'localhost')
    CELERY_RESULT_BACKEND = 'redis://%s:6379/0' % os.getenv('RHOST', 'localhost')


class TestingConfig(DevelopmentConfig):
    DEBUG = True
    SMTP_HOST = 'smtpdm.aliyun.com'
    SMTP_PORT = 80
    SMTP_SENDER = 'sender@mail.gakki.tech'
    SMTP_LOGIN = 'sender@mail.gakki.tech'
    SMTP_PASSWORD = 'ZSsdlh12345'

    ETH_ENCRYPT_PASSWORD = '123456'
    BLOCKLINK_ERC20_CONTRACT_ADDRESS = '0xd7cddd45629934c2f6ed3b63217bd8085d7c14a8'  # FIXME: this is AVH address for development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
                              "mysql+pymysql://root:123456@192.168.1.128:3306/blocklinkbackend_dev"

    SWEEP_TO_ETH_ADDRESS = '0xb4e71a0F74a09dDf76c47234d31111DAcbe320D2'

    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_POOL_SIZE = 200

    NEED_CAPTCHA = False

    ETHERSCAN_API_KEY = 'QQGM9I82DH2H9M7J8J21FHADIFBIDFQHWE'

    CELERY_BROKER_URL = 'redis://%s:6379/0' % os.getenv('RHOST', 'localhost')
    CELERY_RESULT_BACKEND = 'redis://%s:6379/0' % os.getenv('RHOST', 'localhost')


class ProductionConfig(Config):
    SMTP_HOST = 'smtpdm.aliyun.com'
    SMTP_PORT = 80
    SMTP_SENDER = 'sender@mail.gakki.tech'
    SMTP_LOGIN = 'sender@mail.gakki.tech'
    SMTP_PASSWORD = 'ZSsdlh12345'

    ETH_ENCRYPT_PASSWORD = '12345ssdlh'
    BLOCKLINK_ERC20_CONTRACT_ADDRESS = ''  # FIXME
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
                              "mysql+pymysql://root:123456@192.168.1.128:3306/blocklinkbackend_production"

    SWEEP_TO_ETH_ADDRESS = os.getenv('SWEEP_TO_ETH_ADDRESS', None)

    MIN_SWEEP_BLOCKLINK_TOKEN_AMOUNT = (10 * (10**18))  # 以太充值账户中最少多少个blocklink 的ETH ERC20 token代币才进行归账操作

    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_POOL_SIZE = 200

    NEED_CAPTCHA = True

    ETHERSCAN_API_KEY = 'QQGM9I82DH2H9M7J8J21FHADIFBIDFQHWE'

    CELERY_BROKER_URL = 'redis://%s:6379/0' % os.getenv('RHOST', 'localhost')
    CELERY_RESULT_BACKEND = 'redis://%s:6379/0' % os.getenv('RHOST', 'localhost')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
