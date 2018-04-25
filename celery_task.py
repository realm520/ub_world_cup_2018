# coding: utf8
import helpers
from app import celery


@celery.task(name='async_send_email')
def async_send_email(to_address, subject, content):
    print("async_send_email to %s" % to_address)
    helpers.send_email(to_address, subject, content)


@celery.task(name='crawl_eth_token_deposit')
def crawl_eth_token_deposit():
    """从etherscan.io上采集eth上需要的ERC20代币的充值记录"""
    print("crawl_eth_token_deposit")
    # TODO