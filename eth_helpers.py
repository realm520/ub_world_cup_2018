# coding: utf8

import eth_account
import base64
import requests
from decimal import Decimal
from Crypto import Random
from Crypto.Cipher import AES
import helpers


def generate_eth_account():
    return eth_account.Account.create()


def encrypt_eth_privatekey(private_key, password):
    if len(password) < 16:
        password = password + ('0'*(16-len(password))).encode('utf8')
    encoder = helpers.AESCipher(password)
    enrypted = encoder.encrypt(private_key)
    return base64.b64encode(enrypted).decode('utf8')


def decrypt_eth_privatekey(encrypted_private_key, password):
    if len(password) < 16:
        password = password + ('0'*(16-len(password))).encode('utf8')
    encoder = helpers.AESCipher(password)
    decrypted = encoder.decrypt(base64.b64decode(encrypted_private_key))
    return decrypted


class EthAccountBalance(object):
    def __init__(self, address, balance, token_contract_address=None, precision=18):
        self.address = address
        self.balance = balance
        self.balance_str = str(balance)
        self.token_contract_address = token_contract_address  # None表示是以太，其他是token合约地址
        self.precision = precision
        self.simple_balance = Decimal(balance) / Decimal(10 ** precision)


def query_eth_addresses_balances_of_eth(eth_addresses):
    """查询多个eth地址中的eth余额"""
    from app import app
    api_url = "https://api.etherscan.io/api?module=account&action=balancemulti&address=%s&tag=latest&apikey=%s" % (
    ','.join(eth_addresses), app.config['ETHERSCAN_API_KEY'])
    res = requests.get(api_url).json()
    if res.get('status', None) == "1" or res.get('status', None) == "0":
        result_json = res.get('result', [])
        result = {item['account']: EthAccountBalance(item['account'], int(item['balance'])) for item in
                  result_json}
        return result
    else:
        raise Exception("query eth address balance error %s" % str(res))


def query_eth_addresses_balances_of_token(eth_addresses, token_contract_address):
    """查询多个eth地址中的token代币余额"""
    result = {}
    for eth_address in eth_addresses:
        api_url = "https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress=%s&address=%s&tag=latest&apikey=YourApiKeyToken" %(token_contract_address, eth_address)
        res = requests.get(api_url).json()
        if res.get('status', None) == "1":
            balance = int(res.get('result', '0'))
            result[eth_address] = EthAccountBalance(eth_address, balance, token_contract_address)
    return result
