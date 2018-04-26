# coding: utf8
import helpers
from app import celery, redis_store, config_model, app, db
from models import User, EthAccount, EthTokenDepositOrder
from logging_config import logger
import requests
import datetime
from decimal import Decimal


@celery.task(name='async_send_email')
def async_send_email(to_address, subject, content):
    print("async_send_email to %s" % to_address)
    helpers.send_email(to_address, subject, content)


def get_last_crawled_eth_block_height():
    key = "%s_last_crawled_eth_block_height" % config_model
    height = redis_store.get(key)
    if height is not None:
        try:
            return int(height)
        except Exception as _:
            return None
    else:
        return None


def update_last_crawled_eth_block_height(block_height):
    key = "%s_last_crawled_eth_block_height" % config_model
    redis_store.set(key, block_height)


def get_eth_token_deposit_address():
    """获取以太token充值地址列表"""
    accounts = db.session.query(EthAccount).order_by(EthAccount.created_at.desc()).all()
    addresses = set()
    for account in accounts:
        addresses.add(account.address)
    return list(addresses)


def get_eth_latest_block_height():
    """获取eth最新块高度"""
    api_key = app.config['ETHERSCAN_API_KEY']
    api_url = "https://api.etherscan.io/api?module=proxy&action=eth_blockNumber&apikey=%s" % api_key
    res = requests.get(api_url).json()
    if res['result'] is None:
        raise IOError("fetch eth latest block height failed %s" % str(res))
    return int(res['result'], 16)


# TODO: 需要一个后台任务查账检查user的balance和充值流水是否一致(eth_address没变的情况下)


def direct_crawl_eth_token_deposits():
    addresses = get_eth_token_deposit_address()
    logger.debug("eth addresses count: %d" % len(addresses))
    last_crawled_eth_block_height = get_last_crawled_eth_block_height()
    start_blockheight = 0 if last_crawled_eth_block_height is None else last_crawled_eth_block_height
    api_key = app.config['ETHERSCAN_API_KEY']
    contract_addr = app.config['BLOCKLINK_ERC20_CONTRACT_ADDRESS']
    assert contract_addr is not None and len(contract_addr) > 0
    min_confirmations = 5
    latest_height = get_eth_latest_block_height()
    has_error = False

    for address in addresses:
        token_txs_api_url = "http://api.etherscan.io/api?module=account&action=tokentx&address=%s&startblock=%d&endblock=%d&sort=asc&apikey=%s" % (address, start_blockheight, latest_height, api_key)
        try:
            res = requests.get(token_txs_api_url).json()
            if str(res.get('status', None)) == '0' and res.get('message') == 'No transactions found':
                continue
            if int(res['status']) == 1:
                txs = res['result']
                for tx in txs:
                    tx_block_number = int(tx['blockNumber'])
                    tx_timestamp = datetime.datetime.fromtimestamp(int(tx['timeStamp']))
                    tx_hash = tx['hash'].lower()
                    nonce = tx['nonce']
                    block_hash = tx['blockHash'].lower()
                    from_addr = tx['from'].lower()
                    tx_contract_addr = tx['contractAddress'].lower()
                    to_addr = tx['to'].lower()
                    tx_value = int(tx['value'])
                    tx_token_name = tx['tokenName']
                    tx_token_symbol = tx['tokenSymbol']
                    if tx_token_symbol is None or len(tx_token_symbol) < 1:
                        continue
                    try:
                        tx_token_decimal = int(tx['tokenDecimal'])
                    except Exception as e:
                        continue
                    tx_gas = int(tx['gas'])
                    tx_gas_price = int(tx['gasPrice'])
                    tx_gas_used = int(tx['gasUsed'])
                    tx_confirmations = int(tx['confirmations'])
                    if str(tx_contract_addr).lower() != str(contract_addr).lower():
                        continue
                    if to_addr != address.lower() or from_addr.lower() == address.lower():
                        continue
                    if tx_confirmations < min_confirmations:
                        continue
                    deposit_tx = db.session.query(EthTokenDepositOrder).filter_by(trx_id=tx_hash).first()
                    if deposit_tx is not None:
                        continue
                    user = db.session.query(User).filter_by(eth_address=address).first()
                    deposit_tx = EthTokenDepositOrder(from_addr, to_addr, str(tx_value), tx_token_decimal, tx_hash, tx_timestamp,
                                                      tx_token_symbol, tx_block_number, tx_contract_addr, 'SUCCESS',
                                                      user_id=user.id if user else None)
                    db.session.add(deposit_tx)
                    # add unpayed_balance to user
                    if user is not None:
                        user.unpayed_balance = str(Decimal(user.unpayed_balance) + (Decimal(tx_value) / Decimal(10**tx_token_decimal)))
                        db.session.add(user)
                    logger.info("eth token tx crawled: %s" % tx)
                db.session.commit()
        except Exception as e:
            logger.error("process eth tx error", e)
            has_error = True
            db.session.rollback()

    if not has_error:
        update_last_crawled_eth_block_height(latest_height)


@celery.task(name='crawl_eth_token_deposit')
def crawl_eth_token_deposits():
    """从etherscan.io上采集eth上需要的ERC20代币的充值记录"""
    logger.info("crawl_eth_token_deposits task")
    direct_crawl_eth_token_deposits()
