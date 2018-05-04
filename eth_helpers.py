# coding: utf8

import eth_account
import base64
import requests
from decimal import Decimal
from Crypto import Random
from Crypto.Cipher import AES
import eth_utils
import eth_account
import helpers
import json


def generate_eth_account():
    return eth_account.Account.create()


def encrypt_eth_privatekey(private_key, password):
    if len(password) < 16:
        password = password + ('0' * (16 - len(password))).encode('utf8')
    encoder = helpers.AESCipher(password)
    enrypted = encoder.encrypt(private_key)
    return enrypted.hex()


def decrypt_eth_privatekey(encrypted_private_key, password):
    if len(password) < 16:
        password = password + ('0' * (16 - len(password))).encode('utf8')
    encoder = helpers.AESCipher(password)
    decrypted = encoder.decrypt(bytes.fromhex(encrypted_private_key))
    return decrypted


def try_decrypt_eth_privatekey(encrypted_private_key, password):
    try:
        return decrypt_eth_privatekey(encrypted_private_key, password)
    except Exception as _:
        return None


class EthAccountBalance(object):
    def __init__(self, address, balance, token_contract_address=None, precision=18):
        self.address = address
        self.balance = balance
        self.balance_str = str(balance)
        self.token_contract_address = token_contract_address  # None表示是以太，其他是token合约地址
        self.precision = precision
        self.simple_balance = Decimal(balance) / Decimal(10 ** precision)

    def __repr__(self):
        return json.dumps({
            'address': self.address,
            'balance': self.balance_str,
            'token_contract_address': self.token_contract_address,
            'precision': self.precision,
            'simple_balance': str(self.simple_balance),
        })


def query_eth_addresses_balances_of_eth(eth_addresses):
    """查询多个eth地址中的eth余额"""
    from app import app
    api_url = "https://api.etherscan.io/api?module=account&action=balancemulti&address=%s&tag=latest&apikey=%s" % (
        ','.join(eth_addresses), app.config['ETHERSCAN_API_KEY'])
    res = requests.get(api_url, verify=False).json()
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
        api_url = "https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress=%s&address=%s&tag=latest&apikey=YourApiKeyToken" % (
        token_contract_address, eth_address)
        res = requests.get(api_url, verify=False).json()
        if res.get('status', None) == "1":
            balance = int(res.get('result', '0'))
            result[eth_address] = EthAccountBalance(eth_address, balance, token_contract_address)
    return result


def get_eth_method_id(method_signature):
    """
    获取eth中某个合约API的method id，返回16进制字符串
    <<< get_eth_method_id('baz(uint32,bool)') === 'cdcd77c0
    """
    return eth_utils.crypto.keccak(method_signature.encode('utf8'))[:4].hex()


def wrap_eth_method_parameter(value):
    """
    把eth合约调用中的参数左边用0补齐到32 bytes，返回16进制字符串
    <<< wrap_eth_method_parameter(69) === '0000000000000000000000000000000000000000000000000000000000000045'
    <<< wrap_eth_method_parameter(true) === '0000000000000000000000000000000000000000000000000000000000000001'
    """
    if isinstance(value, str) and value.startswith('0x'):
        bytes_value = eth_utils.to_bytes(hexstr=value)
    else:
        bytes_value = eth_utils.to_bytes(value)
    if len(bytes_value) < 32:
        bytes_value = b'\0' * (32 - len(bytes_value)) + bytes_value
    return bytes_value.hex()


def make_eth_call_params(from_addr, to_addr, gas, gas_price, eth_value_to_transfer, method_signature,
                         method_parameters, nonce):
    """

    :param from_addr: 20 Bytes - The address the transaction is sent from
    :param to_addr: 20 Bytes - The address the transaction is directed to
    :param gas: Integer of the gas provided for the transaction execution. eth_call consumes zero gas, but this parameter may be needed by some executions
    :param gas_price: Integer of the gasPrice used for each paid gas
    :param eth_value_to_transfer: Integer of the value sent with this transaction
    :param method_signature: method's signatre to be called, eg. baz(uint32,bool)
    :param method_parameters: parameters to call eth contract's method
    :param nonce: account nonce+1
    :return:
    """
    data = '0x' + get_eth_method_id(method_signature)
    for param in method_parameters:
        data += wrap_eth_method_parameter(param)
    return {
        # 'from': from_addr,
        'to': to_addr,
        'gas': gas,
        'gasPrice': gas_price,
        'value': eth_value_to_transfer,
        'data': data,
        'nonce': nonce,
    }


myetherapi_endpoint = 'https://api.myetherapi.com/eth'


def call_myetherapi_rpc(method, params):
    """
    Executes a new message call immediately without creating a transaction on the block chain.
    """
    try:
        res = requests.post(myetherapi_endpoint, json={
            'jsonrpc': '2.0',
            'method': method,
            'params': params,
            'id': 1,
        }, verify=False)
        res_json = res.json()
        if res_json.get('result', None) is not None:
            return res_json['result']
        raise Exception(str(res))
    except Exception as e:
        raise e


def send_eth_rawtransaction_to_ether(data):
    """
    Creates new message call transaction or a contract creation for signed transactions
    :param data: The signed transaction data.
    """
    # return call_myetherapi_rpc('eth_sendRawTransaction', [data])
    # TODO: use proxy api
    from web3 import Web3, HTTPProvider, IPCProvider
    from app import app
    geth_rpc_url = app.config['GETH_RPC_URL']
    web3 = Web3(HTTPProvider(geth_rpc_url))
    return web3.eth.sendRawTransaction(data).hex()


def get_eth_address_nonce(eth_address):
    """获取某个以太地址的account nonce"""
    from app import app
    etherscan_api_key = app.config['ETHERSCAN_API_KEY']
    api_url = "https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address=%s&tag=latest&apikey=%s" % (eth_address, etherscan_api_key)
    res = requests.get(api_url, verify=False)
    result = res.json().get('result', None)
    if result.startswith('0x'):
        result = result[2:]
    return int(result, 16)


def eth_signtransaction(transaction_dict, eth_private_key):
    """对以太交易内容进行签名"""
    tx = {}
    for k, v in transaction_dict.items():
        tx[k] = v
    if tx.get('chainId', None) is None:
        tx['chainId'] = 1
    res = eth_account.Account.signTransaction(tx, eth_private_key)
    hex_str = res['rawTransaction'].hex()
    return hex_str


def eth_base16_str_to_bytes(eth_data_hex):
    """16进制的以太字符串转换成字节数组"""
    if eth_data_hex.startswith('0x'):
        eth_data_hex = eth_data_hex[2:]
    return bytes.fromhex(eth_data_hex)


def get_eth_contract_token_transfer_signature():
    return "transfer(address,uint256)"


def get_eth_contract_balance_of_signature():
    return "balanceOf(address)"
