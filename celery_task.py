# coding: utf8
import helpers
from app import celery, redis_store, config_model, app, db
from models import User, EthAccount, EthTokenDepositOrder, EthTokenSweepTransaction
from logging_config import logger
import eth_helpers
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
        token_txs_api_url = "http://api.etherscan.io/api?module=account&action=tokentx&address=%s&startblock=%d&endblock=%d&sort=asc&apikey=%s" % (
            address, start_blockheight, latest_height, api_key)
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
                    deposit_tx = EthTokenDepositOrder(from_addr, to_addr, str(tx_value), tx_token_decimal, tx_hash,
                                                      tx_timestamp,
                                                      tx_token_symbol, tx_block_number, tx_contract_addr, 'SUCCESS',
                                                      user_id=user.id if user else None,
                                                      simple_token_amount=Decimal(tx_value) / Decimal(
                                                          10 ** tx_token_decimal))
                    db.session.add(deposit_tx)
                    # add unpayed_balance to user
                    if user is not None:
                        user.unpayed_balance = str(
                            Decimal(user.unpayed_balance) + (Decimal(tx_value) / Decimal(10 ** tx_token_decimal)))
                        db.session.add(user)
                    logger.info("eth token tx crawled: %s" % tx)
                db.session.commit()
        except Exception as e:
            logger.error("process eth tx error", e)
            has_error = True
            db.session.rollback()

    if not has_error:
        update_last_crawled_eth_block_height(latest_height)


@celery.task(name='crawl_eth_token_deposits')
def crawl_eth_token_deposits():
    """从etherscan.io上采集eth上需要的ERC20代币的充值记录"""
    logger.info("crawl_eth_token_deposits task")
    direct_crawl_eth_token_deposits()


def sweep_deposit_eth_accounts_balances():
    """做以太充值账户的归账操作"""
    # 计算合约的一次转账操作需要的gas(可以估计一个固定值)
    token_contract_addr = app.config['BLOCKLINK_ERC20_CONTRACT_ADDRESS']
    gas_limit = 100000  # TODO: 不同token合约可能需要不同的gas_limit
    gas_price = 1 * (10**9)
    encrypt_password = app.config['ETH_ENCRYPT_PASSWORD'].encode('utf8')
    min_sweep_blocklink_token_amount = app.config['MIN_SWEEP_BLOCKLINK_TOKEN_AMOUNT']
    sweep_to_eth_address = app.config['SWEEP_TO_ETH_ADDRESS']
    sweep_gas_spender_eth_address = app.config['SWEEP_GAS_SPENDER_ETH_ADDRESS']
    sweep_gas_spender_eth_private_key = app.config['SWEEP_GAS_SPENDER_ETH_PRIVATE_KEY']
    # TODO: 充值账户中的ETH的归账（有可能是sweep_gas_spender转给这个地址的，所以不直接还给用户）
    try:
        eth_accounts = db.session.query(EthAccount).all()
        token_balances_of_accounts = eth_helpers.query_eth_addresses_balances_of_token(
            [account.address for account in eth_accounts], token_contract_addr)
        eth_balances_of_accounts = eth_helpers.query_eth_addresses_balances_of_eth(
            [account.address for account in eth_accounts])
        print(token_balances_of_accounts, eth_balances_of_accounts)
        nonce_of_sweep_gas_spender_address = eth_helpers.get_eth_address_nonce(sweep_gas_spender_eth_address)
        for eth_account in eth_accounts:
            eth_privatekey = eth_helpers.try_decrypt_eth_privatekey(eth_account.encrypted_private_key, encrypt_password)
            # 检查以太充值账户的私钥和地址是否匹配，如果不匹配，跳过这个以太地址
            if eth_privatekey is None:
                logger.info(
                    "found eth address %s private key error when sweeping deposit eth accounts" % str(eth_account.address))
                continue
            recently_sweep_history = db.session.query(EthTokenSweepTransaction) \
                .filter_by(from_address=eth_account.address) \
                .filter(
                EthTokenSweepTransaction.created_at > (datetime.datetime.utcnow() - datetime.timedelta(hours=3))) \
                .order_by(EthTokenSweepTransaction.created_at.desc()).first()
            if recently_sweep_history is not None:
                # 如果此地址有3小时内的归账操作，跳过
                continue
            token_balance = token_balances_of_accounts.get(eth_account.address,
                                                           eth_helpers.EthAccountBalance(eth_account.address, 0,
                                                                                         token_contract_addr))
            if token_balance.balance < min_sweep_blocklink_token_amount:
                # token余额太少的不归账
                print(token_balance.balance, token_balance.simple_balance, min_sweep_blocklink_token_amount)
                logger.info(
                    "eth account has too little blocklink ERC20 token to sweep(%s)" % str(token_balance.simple_balance))
                continue
            eth_balance = eth_balances_of_accounts.get(eth_account.address,
                                                       eth_helpers.EthAccountBalance(eth_account.address, 0))
            if int(eth_balance.balance) <= (gas_price * gas_limit):
                # 以太充值账户的ETH余额不够做token转账的gas，从其他账户转一点以太过去
                to_send_eth_amount = gas_limit * gas_price
                transfer_eth_for_gas_tx_dict = {
                    # 'from': sweep_gas_spender_eth_address,
                    'to': eth_account.address,
                    'value': to_send_eth_amount,
                    'gas': 25200,  # ETH转账需要的gas
                    'gasPrice': gas_price,
                    'nonce': nonce_of_sweep_gas_spender_address,
                }
                nonce_of_sweep_gas_spender_address += 1
                signed_raw_tx = eth_helpers.eth_signtransaction(transfer_eth_for_gas_tx_dict,
                                                                sweep_gas_spender_eth_private_key)
                logger.info("signed raw tx for send eth is: %s" % str(signed_raw_tx))
                tx_id = eth_helpers.send_eth_rawtransaction_to_ether(signed_raw_tx)
                logger.info(
                    "response of transfer gas eth from sweep address to %s is %s" % (eth_account.address, str(tx_id)))
                # 等待下一个任务周期，这个以太充值地址有ETH后再继续归账
                continue
            # 发起从以太充值账户转账token到归账地址的交易并广播
            account_nonce = eth_helpers.get_eth_address_nonce(eth_account.address)
            transfer_token_tx_dict = eth_helpers.make_eth_call_params(eth_account.address, token_contract_addr,
                                                                      gas_limit, gas_price, 0,
                                                                      eth_helpers.get_eth_contract_token_transfer_signature(),
                                                                      [sweep_to_eth_address, int(token_balance.balance)],
                                                                      account_nonce)
            signed_raw_tx = eth_helpers.eth_signtransaction(transfer_token_tx_dict, eth_privatekey)
            logger.info("signed raw tx for send ERC20 token %s from %s to %s: %s" % (str(token_balance.simple_balance), eth_account.address, sweep_to_eth_address, str(signed_raw_tx)))
            tx_id = eth_helpers.send_eth_rawtransaction_to_ether(signed_raw_tx)
            logger.info(
                "response of transfer token from %s to sweep eth address is %s" % (eth_account.address, str(tx_id)))

            # 把归账交易记录到数据库
            sweep_tx = EthTokenSweepTransaction(tx_id, eth_account.address, sweep_to_eth_address, token_contract_addr,
                                                token_balance.simple_balance)
            db.session.add(sweep_tx)
            db.session.commit()
            logger.info("processed one token sweep(amount %s) transaction of %s to %s" % (
            str(token_balance.simple_balance), eth_account.address, sweep_to_eth_address))
    except Exception as e:
        logger.error("sweep deposit eth accounts balances error: %s" % str(e))
        db.session.rollback()


@celery.task(name='sweep_deposit_eth_accounts_balances')
def sweep_deposit_eth_accounts_balances_task():
    logger.info("sweep_deposit_eth_accounts_balances task")
    sweep_deposit_eth_accounts_balances()

# TODO: 检查数据库中归账交易并更新状态
