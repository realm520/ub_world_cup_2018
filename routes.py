# coding: utf8
from __future__ import print_function
from flask import request, session
from flask_cors import CORS, cross_origin
from app import app, db, jsonrpc, redis_store
from models import User, EthAccount, EthTokenDepositOrder
import bcrypt
import helpers
import eth_helpers
import uuid
import base64
import json
import pickle
import time
import jwt
from flask_jsonrpc.exceptions import InvalidParamsError
from decimal import Decimal
from helpers import allow_cross_domain
from functools import wraps
from datetime import datetime
from sqlalchemy import or_
import captcha_helpers
import celery_task
from logging_config import logger
import error_utils

CORS(app)


@app.teardown_request
def teardown_request(exception):
    if exception:
        db.session.rollback()
    db.session.remove()


@app.route('/')
def hello_world():
    return 'Hello World!'


X_TOKEN_HEADER_KEY = 'X-TOKEN'


# TODO: sweep tokens to offline wallet, backup, 对账. 需要增加一个超级管理员，超级管理员可以看到各以太账户的地址，地址的ETH余额，TOKEN余额，以及查看私钥，手动进行归账。或者调用geth/myetherwallet api
# TODO: 归账前需要转一点以太到充值账户做手续费（如果确定充值账户的代币需要归账，太少可以先不归账）

def check_auth(f):
    @wraps(f)
    def _f(*args, **kwargs):
        try:
            if session.get('user', None) is not None:
                return f(*args, **kwargs)
            token = request.headers.get(X_TOKEN_HEADER_KEY, None)
            if token is None or len(token) < 1:
                raise error_utils.AutoTokenNotFoundError()
            user_id = helpers.decode_auth_token(token)
            user = User.query.get(user_id)
            if user is None or user.disabled:
                raise error_utils.UserNotFoundByAuthTokenError(token)
            session['user'] = user.to_print_json()
            session['user_id'] = user.id
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError as _:
            raise error_utils.AuthTokenExpiredError()
        except jwt.InvalidTokenError as _:
            raise error_utils.AuthTokenInvalidError()
        except Exception as e:
            raise error_utils.OtherError(str(e))

    return _f


@jsonrpc.method('App.viewProfile()')
@allow_cross_domain
@check_auth
def view_profile():
    """API to view current user profile"""
    user_json = session['user']
    user = User.query.get(user_json['id'])
    user_json = user.to_print_json()
    session['user'] = user_json
    return user_json


@jsonrpc.method('App.myDepositHistory(offset=int,limit=int,review_state=bool,all=bool)')
@allow_cross_domain
@check_auth
def query_my_deposit_history(offset, limit, review_state, all):
    """查询当前用户的充值流水"""
    if offset is None or offset < 0:
        offset = 0
    if limit is None or limit < 1:
        limit = 20
    if all is None:
        all = True
    user_json = session['user']
    user = User.query.get(user_json['id'])
    q = EthTokenDepositOrder.query.filter_by(user_id=user.id)
    if not all:
        q = q.filter_by(review_state=review_state)
    orders = q.order_by(EthTokenDepositOrder.created_at.desc()).offset(offset).limit(limit).all()
    order_dicts = [order.to_dict() for order in orders]
    q = EthTokenDepositOrder.query.filter_by(user_id=user.id)
    if not all:
        q = q.filter_by(review_state=review_state)
    total = q.count()
    return {
        'items': order_dicts,
        'offset': offset,
        'limit': limit,
        'total': total,
    }


@jsonrpc.method('App.allUsersSumUnpayedBalances()')
@allow_cross_domain
@check_auth
def query_all_users_sum_unpayed_balances():
    """管理员查询所有用户的总的未支付余额"""
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise error_utils.PermissionDeniedError()
    users = User.query.all()
    sum = Decimal(0)
    for user in users:
        sum += Decimal(user.unpayed_balance)
    return str(sum)


@jsonrpc.method(
    'App.listUsers(offset=int,limit=int,keyword=str)')
@allow_cross_domain
@check_auth
def query_users(offset, limit, keyword):
    """
    管理员查询所有用户的信息
    :param offset: 0-based偏移量
    :param limit: 本次最多取的记录数量
    :param keyword: 用户邮箱或者充值地址或者blocklink地址
    :return:
    """
    if offset is None or offset < 0:
        offset = 0
    if limit is None or limit < 1:
        limit = 20
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise error_utils.PermissionDeniedError()

    def make_query(keyword):
        q = User.query
        if keyword is not None and len(keyword) > 0:
            q = q.filter(or_(User.email == keyword, User.eth_address == keyword, User.blocklink_address == keyword))
        return q

    users = make_query(keyword).order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    total = make_query(keyword).count()
    users_dicts = [user.to_print_json() for user in users]
    return helpers.make_paginator_response(offset, limit, total, users_dicts)


@jsonrpc.method(
    'App.getUser(user_id=int)')
@allow_cross_domain
@check_auth
def query_user(user_id):
    """
    管理员查看用户信息
    :param user_id:
    :return:
    """
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise error_utils.PermissionDeniedError()
    user = User.query.filter_by(id=user_id)
    if user is None:
        return None
    else:
        return user.to_print_json()


@jsonrpc.method(
    'App.getEthAccount(address=str)')
@allow_cross_domain
@check_auth
def query_eth_account(address):
    """
    管理员查看充值账户（以太账户）信息
    :param address:
    :return:
    """
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise error_utils.PermissionDeniedError()
    account = EthAccount.query.filter_by(address=address)
    if account is None:
        return None
    else:
        account_dict = account.to_dict()
        balances = eth_helpers.query_eth_addresses_balances_of_eth([account.address])
        token_contract_address = app.config['BLOCKLINK_ERC20_CONTRACT_ADDRESS']
        token_balances = eth_helpers.query_eth_addresses_balances_of_token([account.address], token_contract_address)
        account_dict['eth_balance'] = str(balances.get(account.address, eth_helpers.EthAccountBalance(account.address, 0)).simple_balance)
        account_dict['token_balance'] = str(token_balances.get(account.address,
                                                           eth_helpers.EthAccountBalance(account.address, 0,
                                                                                         token_contract_address)).simple_balance)
        return account_dict


@jsonrpc.method(
    'App.listDepositEthAccounts(offset=int,limit=int,keyword=str)')
@allow_cross_domain
@check_auth
def query_deposit_eth_accounts(offset, limit, keyword):
    """
    管理员查询系统中的各充值账户（以太账户）的信息
    :param offset: 0-based偏移量
    :param limit: 取的记录数量
    :param keyword: 以太充值地址或所属用户邮箱
    :return:
    """
    if offset is None or offset < 0:
        offset = 0
    if limit is None or limit < 1:
        limit = 20
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise error_utils.PermissionDeniedError()

    def make_query(keyword):
        q = EthAccount.query
        if keyword is not None and len(keyword) > 0:
            q = q.join(User, User.eth_address == EthAccount.address)
            q = q.filter(or_(EthAccount.address == keyword, User.email == keyword))
        return q

    eth_accounts = make_query(keyword).order_by(EthAccount.created_at.desc()).offset(offset).limit(limit).all()
    total = make_query(keyword).count()
    eth_accounts_dicts = []
    eth_addresses = [account.address for account in eth_accounts]
    eth_balances = eth_helpers.query_eth_addresses_balances_of_eth(eth_addresses)
    token_contract_address = app.config['BLOCKLINK_ERC20_CONTRACT_ADDRESS']
    token_balances = eth_helpers.query_eth_addresses_balances_of_token(eth_addresses, token_contract_address)
    for eth_account in eth_accounts:
        eth_account_dict = eth_account.to_dict()
        eth_account_dict['eth_balance'] = str(eth_balances.get(eth_account.address,
                                                           eth_helpers.EthAccountBalance(eth_account.address, 0)).simple_balance)
        eth_account_dict['token_balance'] = str(token_balances.get(eth_account.address,
                                                               eth_helpers.EthAccountBalance(eth_account.address, 0,
                                                                                             token_contract_address)).simple_balance)
        eth_accounts_dicts.append(eth_account_dict)
    return helpers.make_paginator_response(offset, limit, total, eth_accounts_dicts)


@jsonrpc.method(
    'App.usersDepositHistory(user_id=str,offset=int,limit=int,review_state=int,amount_min=str,amount_max=str,min_timestamp=int,keyword=str)')
@allow_cross_domain
@check_auth
def query_users_deposit_history(user_id, offset, limit, review_state, amount_min, amount_max, min_timestamp, keyword):
    """
    管理员查询所有用户的充值流水
    :param user_id: 用户id
    :param offset: 0-based偏移量
    :param limit: 取的记录的数量
    :param review_state: null/0表示不筛选，1表示审核中，2表示兑换成功，3表示拒绝请求
    :param amount_min: 最小金额
    :param amount_max: 最大金额
    :param min_timestamp: 发起的最小时间戳（秒数）
    :param keyword 搜索关键字，用户名或充值地址
    :return:
    """
    if offset is None or offset < 0:
        offset = 0
    if limit is None or limit < 1:
        limit = 20
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise error_utils.PermissionDeniedError()

    def make_query(keyword):
        q = EthTokenDepositOrder.query
        if user_id is not None:
            q = q.filter_by(user_id=user_id)
        if review_state == 1:
            q = q.filter_by(review_state=None)
        elif review_state == 2:
            q = q.filter_by(review_state=True)
        elif review_state == 3:
            q = q.filter_by(review_state=False)
        else:
            if review_state != 0 and review_state is not None:
                raise error_utils.OtherError("invalid review_state params")

        if amount_min is not None:
            q = q.filter(EthTokenDepositOrder.simple_token_amount >= amount_min)
        if amount_max is not None:
            q = q.filter(EthTokenDepositOrder.simple_token_amount <= amount_max)
        if min_timestamp is not None:
            q = q.filter(EthTokenDepositOrder.created_at >= datetime.utcfromtimestamp(min_timestamp))
        if keyword is not None and len(keyword.strip()) > 0:
            keyword = keyword.strip()
            q = q.join(User, User.id == EthTokenDepositOrder.user_id)
            q = q.filter(or_(User.eth_address == keyword, User.email == keyword))
        return q

    orders = make_query(keyword).order_by(EthTokenDepositOrder.created_at.desc()).offset(offset).limit(limit).all()
    # 关联表的信息
    order_dicts = []
    for order in orders:
        order_obj = order.to_dict()
        if order.review_lock_by_user_id is not None:
            user = User.query.filter_by(id=order.review_lock_by_user_id).first()
            if user is not None:
                order_obj['review_lock_by_user'] = user.to_print_json()
        if order.user_id is not None:
            user = User.query.filter_by(id=order.user_id).first()
            if user is not None:
                order_obj['user'] = user.to_print_json()
        order_dicts.append(order_obj)
    total = make_query(keyword).count()
    return {
        'items': order_dicts,
        'offset': offset,
        'limit': limit,
        'total': total,
    }


@jsonrpc.method('App.lockDepositOrder(order_id=int)')
@allow_cross_domain
@check_auth
def lock_deposit_order(order_id):
    """管理员锁定某个充值流水，避免两个管理员都去做这个充值流水的转账操作"""
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise error_utils.PermissionDeniedError()
    order = EthTokenDepositOrder.query.filter_by(id=order_id).first()
    if order is None:
        raise error_utils.DepositOrderNotFoundError()
    if order.review_state is not None:
        raise error_utils.DepositOrderProcessedBeforeError()
    if order.review_lock_by_user_id is not None:
        raise error_utils.DepositOrderLockedError()
    order.review_lock_by_user_id = cur_user.id
    order.updated_at = datetime.utcnow()
    db.session.add(order)
    db.session.commit()
    return order.to_dict()


@jsonrpc.method('App.unlockDepositOrder(order_id=int)')
@allow_cross_domain
@check_auth
def unlock_deposit_order(order_id):
    """管理员解锁某个充值流水，从而此充值流水可以被再次锁定"""
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise error_utils.PermissionDeniedError()
    order = EthTokenDepositOrder.query.filter_by(id=order_id).first()
    if order is None:
        raise error_utils.DepositOrderNotFoundError()
    if order.review_state is not None:
        raise error_utils.DepositOrderProcessedBeforeError()
    if order.review_lock_by_user_id is None:
        raise error_utils.OtherError("this deposit order not locked before")
    order.review_lock_by_user_id = None
    order.updated_at = datetime.utcnow()
    db.session.add(order)
    db.session.commit()
    return order.to_dict()


@jsonrpc.method('App.getOrder(order_id=int)')
@allow_cross_domain
@check_auth
def get_order_info(order_id):
    """管理员获取某个充值流水的信息"""
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise error_utils.PermissionDeniedError()
    order = EthTokenDepositOrder.query.filter_by(id=order_id).first()
    if order is None:
        raise error_utils.DepositOrderNotFoundError()
    return order.to_dict()


@jsonrpc.method('App.processDepositOrder(order_id=int,agree=bool,memo=str,blocklink_trx_id=str,updated_at=int)')
@allow_cross_domain
@check_auth
def process_deposit_order(order_id, agree, memo, blocklink_trx_id, updated_at):
    """管理员处理充值流水的代币兑换"""
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise error_utils.PermissionDeniedError()
    if agree is None:
        raise error_utils.OtherError("please agree or disagree")
    if not helpers.is_valid_blocklink_trx_id(blocklink_trx_id):
        raise error_utils.OtherError("invalid blocklink transaction id")
    order = EthTokenDepositOrder.query.filter_by(id=order_id).first()
    if order is None:
        raise error_utils.DepositOrderNotFoundError()
    if order.review_state is not None:
        raise error_utils.DepositOrderProcessedBeforeError()
    if updated_at is None or updated_at < time.mktime(order.updated_at.utctimetuple()):
        raise error_utils.OtherError("your order data is too old, please refresh it")
    order_with_blocklink_trx_id = EthTokenDepositOrder.query.filter_by(
        blocklink_coin_sent_trx_id=blocklink_trx_id).first()
    if order_with_blocklink_trx_id is not None:
        raise error_utils.BlocklinkTransactionIdUsedError()
    if order.user_id is None:
        raise error_utils.DepositOrderNotReferToUserError()
    user = User.query.get(order.user_id)
    if user is None:
        raise error_utils.UserNotFoundError()
    deposit_amount = Decimal(order.token_amount) / Decimal(10 ** order.token_precision)
    if not helpers.is_blocklink_trx_amount_valid_for_deposit(blocklink_trx_id, user.blocklink_address, deposit_amount):
        raise error_utils.BlocklinkTransactionAmountNotEnoughError()
    order.review_state = agree
    order.review_message = memo

    if agree:
        order.sent_blocklink_coin_admin_user_id = cur_user.id
        order.blocklink_coin_sent_trx_id = blocklink_trx_id
        order.blocklink_coin_sent = True
        user.payed_balance = str(Decimal(user.payed_balance) + deposit_amount)
        user.unpayed_balance = str(Decimal(user.unpayed_balance) - deposit_amount)
        user.updated_at = datetime.utcnow()

    order.updated_at = datetime.utcnow()

    db.session.add(order)
    db.session.commit()
    return order.to_dict()


@jsonrpc.method('App.changeBlocklinkAddress(address=str)')
@allow_cross_domain
@check_auth
def change_blocklink_address(address):
    user_json = session['user']
    if not helpers.is_valid_blocklink_address(address):
        raise error_utils.InvalidBlocklinkAddressFormatError(address)
    user = User.query.get(user_json['id'])
    if user.blocklink_address == address:
        raise error_utils.OtherError("Can't use old blocklink address")
    user.blocklink_address = address
    user.updated_at = datetime.utcnow()
    db.session.add(user)
    db.session.commit()
    return user.to_print_json()


@jsonrpc.method('App.requestRegisterEmailVerifyCode(email=str,picture_code_key=str,picture_verify_code=str)')
@allow_cross_domain
def request_register_email_verify_code(email, picture_code_key, picture_verify_code):
    if app.config['NEED_CAPTCHA']:
        picture_code_info = redis_store.get(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + picture_code_key)
        if picture_code_info is None or pickle.loads(picture_code_info)['code'] != picture_verify_code:
            raise error_utils.InvalidPictureVerifyCodeError()
    token = request.headers.get(X_TOKEN_HEADER_KEY, None)
    if token is None or len(token) < 1:
        key = str(uuid.uuid4())
    else:
        key = token
    code = helpers.generate_captcha_code(6)
    redis_store.set(EMAIL_VERIFY_CODE_CACHE_KEY_PREFIX + key, pickle.dumps({
        'code': code,
        'time': datetime.utcnow(),
    }))
    redis_store.expire(EMAIL_VERIFY_CODE_CACHE_KEY_PREFIX + key, 5 * 60)
    celery_task.async_send_email.delay(email, 'Reset Password', "Your verification code is %s" % code)
    return {
        'key': key,
    }


PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX = 'PVC'
EMAIL_VERIFY_CODE_CACHE_KEY_PREFIX = 'EVC'
EMAIL_RESET_PASSWORD_CACHE_KEY_PREFIX = 'ERPVC'


@jsonrpc.method('App.requestPictureVerifyCode()')
@allow_cross_domain
def request_picture_verify_code():
    """generate picture captcha image"""
    # TODO: check too often
    stream, code = captcha_helpers.generate_verify_image(save_img=False)
    img_base64 = base64.b64encode(stream.getvalue()).decode('utf8')
    token = request.headers.get(X_TOKEN_HEADER_KEY, None)
    if token is None or len(token) < 1:
        key = str(uuid.uuid4())
    else:
        key = token
    redis_store.set(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + key, pickle.dumps({
        'code': code,
        'time': datetime.utcnow(),
    }))
    redis_store.expire(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + key, 3 * 60)
    return {
        'img': img_base64,
        'key': key,
    }


@jsonrpc.method('App.verifyPictureCode(key=str,code=str)')
@allow_cross_domain
def verify_picture_code(key, code):
    # TODO: check too often
    if key is None or code is None or len(key) < 1 or len(code) < 1:
        raise InvalidParamsError()
    if app.config['NEED_CAPTCHA']:
        info = redis_store.get(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + key)
        if info is None:
            return False
        info = pickle.loads(info)
        if info['code'] != code:
            return False
    return True


@jsonrpc.method('App.verifyBlocklinkAddressFormat(address=str)')
@allow_cross_domain
def verify_blocklink_address_format(address):
    return helpers.is_valid_blocklink_address(address)


@jsonrpc.method('App.requestResetPassword(email=str)')
@allow_cross_domain
def request_reset_password(email):
    if not helpers.is_valid_email_format(email):
        raise error_utils.EmailFormatError()
    token = request.headers.get(X_TOKEN_HEADER_KEY, None)
    if token is None or len(token) < 1:
        key = str(uuid.uuid4())
    else:
        key = token
    code = helpers.generate_captcha_code(6)
    redis_store.set(EMAIL_RESET_PASSWORD_CACHE_KEY_PREFIX + key, pickle.dumps({
        'code': code,
        'time': datetime.utcnow(),
    }))
    redis_store.expire(EMAIL_RESET_PASSWORD_CACHE_KEY_PREFIX + key, 5 * 60)
    helpers.send_email(email, 'Reset Password', "Your verification code to reset password is %s" % code)
    return {
        'key': key,
    }


@jsonrpc.method('App.resetPassword(email=str,new_password=str,verify_code=str,key=str)')
@allow_cross_domain
def reset_password(email, new_password, verify_code, key):
    user = User.query.filter_by(email=email).first()
    if user is None:
        raise error_utils.UserNotFoundError()
    if app.config['NEED_CAPTCHA']:
        code_info = redis_store.get(EMAIL_RESET_PASSWORD_CACHE_KEY_PREFIX + key)
        if code_info is None or pickle.loads(code_info)['code'] != verify_code:
            raise error_utils.InvalidEmailVerifyCodeError()

    if not helpers.check_password_format(new_password):
        raise error_utils.PasswordFormatError()
    if helpers.check_password(new_password, user.password):
        raise error_utils.OtherError("can't use old password")
    password_crypted = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
    user.password = password_crypted
    user.updated_at = datetime.utcnow()
    db.session.add(user)
    db.session.commit()
    return user.to_print_json()


@jsonrpc.method('App.updateProfile(email=str,new_password=str,blocklink_address=str,verify_code=str,key=str)')
@allow_cross_domain
@check_auth
def update_profile(email, new_password, blocklink_address, verify_code, key):
    user = User.query.filter_by(email=email).first()
    if user is None:
        raise error_utils.UserNotFoundError()
    if app.config['NEED_CAPTCHA']:
        code_info = redis_store.get(EMAIL_RESET_PASSWORD_CACHE_KEY_PREFIX + key)
        if code_info is None or pickle.loads(code_info)['code'] != verify_code:
            raise error_utils.InvalidEmailVerifyCodeError()

    if not helpers.check_password_format(new_password):
        raise error_utils.PasswordFormatError()
    if helpers.check_password(new_password, user.password):
        raise error_utils.OtherError("can't use old password")
    password_crypted = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
    user.password = password_crypted

    if blocklink_address is not None and len(blocklink_address) > 0:
        if not helpers.is_valid_blocklink_address(blocklink_address):
            raise error_utils.InvalidBlocklinkAddressFormatError(blocklink_address)
        if user.blocklink_address != blocklink_address:
            user.blocklink_address = blocklink_address

    user.updated_at = datetime.utcnow()
    db.session.add(user)
    db.session.commit()
    return user.to_print_json()


@jsonrpc.method('App.logout()')
@allow_cross_domain
@check_auth
def logout():
    """注销退出"""
    session['user'] = None
    session['user_id'] = None
    return True


@jsonrpc.method('App.login(loginname=str,password=str,verify_code=str)')
@allow_cross_domain
def login(loginname, password, verify_code):
    if loginname is None or len(loginname) < 1:
        raise InvalidParamsError()
    # TODO; picture verify code check if this session request too many times
    user = User.query.filter_by(email=loginname).first()
    if user is None:
        raise error_utils.UserNotFoundError()
    if password is None or len(password) < 1:
        raise error_utils.PasswordFormatError()
    if not helpers.check_password(password.encode('utf8'), user.password):
        raise error_utils.InvalidUsernameOrPasswordError()
    token = helpers.encode_auth_token(user.id)
    user_json = user.to_print_json()
    user_json['auth_token'] = token.decode('utf8')
    session['user'] = user.to_print_json()
    session['user_id'] = user.id
    return user_json


@jsonrpc.method(
    'App.register(email=str,password=str,blocklink_address=str,mobile=str,family_name=str,given_name=str,email_verify_code=str,email_code_key=str)')
@allow_cross_domain
def register(email, password, blocklink_address, mobile, family_name, given_name, email_verify_code, email_code_key):
    if not helpers.is_valid_email_format(email):
        raise error_utils.EmailFormatError()
    if email is None or len(email) < 1:
        raise error_utils.EmailFormatError()
    if password is None or len(password) < 6:
        raise error_utils.PasswordFormatError()
    user = User.query.filter_by(email=email).first()
    if user is not None:
        raise error_utils.UserWithEmailExistedError(email)

    if app.config['NEED_CAPTCHA']:
        email_code_info = redis_store.get(EMAIL_VERIFY_CODE_CACHE_KEY_PREFIX + email_code_key)
        if email_code_info is None or pickle.loads(email_code_info)['code'] != email_verify_code:
            raise error_utils.InvalidEmailVerifyCodeError()

    if blocklink_address is not None and not helpers.is_valid_blocklink_address(blocklink_address):
        raise error_utils.InvalidBlocklinkAddressFormatError(blocklink_address)
    if mobile is not None and len(mobile) > 30:
        raise error_utils.InvalidMobilePhoneFormatError()
    eth_account = eth_helpers.generate_eth_account()
    encrypt_password = app.config['ETH_ENCRYPT_PASSWORD']
    password_crypted = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
    user = User(email=email, password=password_crypted, mobile=mobile, eth_address=None,
                blocklink_address=blocklink_address, family_name=family_name, given_name=given_name)
    user.eth_address = eth_account.address.lower()
    db.session.add(user)
    account = EthAccount(eth_account.address.lower(),
                         eth_helpers.encrypt_eth_privatekey(eth_account.privateKey.hex(), encrypt_password))
    assert eth_helpers.decrypt_eth_privatekey(account.encrypted_private_key,
                                              encrypt_password) == eth_account.privateKey.hex()
    db.session.add(account)
    db.session.commit()
    # TODO: daily backup eth address/privatekeys to private admin email
    return user.to_print_json()
