# coding: utf8
from __future__ import print_function
from flask import request, session
from flask_cors import CORS, cross_origin
from app import app, db, jsonrpc, redis_store
from models import User, EthAccount, EthTokenDepositOrder
import bcrypt
import helpers
import uuid
import base64
import json
import pickle
from decimal import Decimal
from helpers import allow_cross_domain
from functools import wraps
from datetime import datetime
import captcha_helpers
import celery_task
from logging_config import logger

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


# TODO: error codes, sweep tokens to offline wallet, backup, 对账

def check_auth(f):
    @wraps(f)
    def _f(*args, **kwargs):
        try:
            if session.get('user', None) is not None:
                return f(*args, **kwargs)
            token = request.headers.get(X_TOKEN_HEADER_KEY, None)
            if token is None or len(token) < 1:
                raise Exception("auth token not found")
            user_id = helpers.decode_auth_token(token)
            user = User.query.get(user_id)
            if user is None or user.disabled:
                raise Exception("user not found")
            session['user'] = user.to_print_json()
            session['user_id'] = user.id
            return f(*args, **kwargs)
        except Exception as e:
            print(e)
            raise e

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


@jsonrpc.method('App.usersDepositHistory(user_id=str,offset=int,limit=int,review_state=bool,all=bool)')
@allow_cross_domain
@check_auth
def query_users_deposit_history(user_id, offset, limit, review_state, all):
    """管理员查询所有用户的充值流水"""
    if offset is None or offset < 0:
        offset = 0
    if limit is None or limit < 1:
        limit = 20
    if all is None:
        all = True
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise Exception("only admin user can visit this api")
    q = EthTokenDepositOrder.query
    if user_id is not None:
        q = q.filter_by(user_id=user_id)
    if not all:
        q = q.filter_by(review_state=review_state)
    orders = q.order_by(EthTokenDepositOrder.created_at.desc()).offset(offset).limit(limit).all()
    order_dicts = [order.to_dict() for order in orders]
    q = EthTokenDepositOrder.query
    if user_id is not None:
        q = q.filter_by(user_id=user_id)
    if not all:
        q = q.filter_by(review_state=review_state)
    total = q.count()
    return {
        'items': order_dicts,
        'offset': offset,
        'limit': limit,
        'total': total,
    }


@jsonrpc.method('App.processDepositOrder(order_id=int,agree=bool,memo=str,blocklink_trx_id=str)')
@allow_cross_domain
@check_auth
def process_deposit_order(order_id, agree, memo, blocklink_trx_id):
    """管理员处理充值流水的代币兑换"""
    cur_user = User.query.get(session['user_id'])
    if cur_user is None or not cur_user.is_admin:
        raise Exception("only admin user can visit this api")
    if agree is None:
        raise Exception("please agree or disagree")
    if not helpers.is_valid_blocklink_trx_id(blocklink_trx_id):
        raise Exception("invalid blocklink transaction id")
    order = EthTokenDepositOrder.query.filter_by(id=order_id).first()
    if order is None:
        raise Exception("Can't find this deposit order")
    if order.review_state is not None:
        raise Exception("this deposit order processed before")
    order_with_blocklink_trx_id = EthTokenDepositOrder.query.filter_by(
        blocklink_coin_sent_trx_id=blocklink_trx_id).first()
    if order_with_blocklink_trx_id is not None:
        raise Exception("this blocklink transaction id used before in this service")
    if order.user_id is None:
        raise Exception("this deposit order not refer to a user")
    user = User.query.get(order.user_id)
    if user is None:
        raise Exception("Can't find user %d" % order.user_id)
    deposit_amount = Decimal(order.token_amount) / Decimal(10 ** order.token_precision)
    if not helpers.is_blocklink_trx_amount_valid_for_deposit(blocklink_trx_id, user.blocklink_address, deposit_amount):
        raise Exception("this blocklink transaction's amount not enough")
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
        raise Exception("Invalid blocklink address format")
    user = User.query.get(user_json['id'])
    if user.blocklink_address == address:
        raise Exception("Can't use old blocklink address")
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
            raise Exception("invalid picture verify code")
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
        raise Exception("invalid params")
    if app.config['NEED_CAPTCHA']:
        info = redis_store.get(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + key, None)
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
        raise Exception("invalid email format")
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
        raise Exception("Can't find user %s" % email)
    if app.config['NEED_CAPTCHA']:
        code_info = redis_store.get(EMAIL_RESET_PASSWORD_CACHE_KEY_PREFIX + key)
        if code_info is None or pickle.loads(code_info)['code'] != verify_code:
            raise Exception("invalid verify code")

    if not helpers.check_password_format(new_password):
        raise Exception("password format error")
    if helpers.check_password(new_password, user.password):
        raise Exception("can't use old password")
    password_crypted = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
    user.password = password_crypted
    user.updated_at = datetime.utcnow()
    db.session.add(user)
    db.session.commit()
    return user.to_print_json()


@jsonrpc.method('App.updateProfile(email=str,new_password=str,blocklink_address=str,verify_code=str,key=str)')
@allow_cross_domain
def update_profile(email, new_password, blocklink_address, verify_code, key):
    user = User.query.filter_by(email=email).first()
    if user is None:
        raise Exception("Can't find user %s" % email)
    if app.config['NEED_CAPTCHA']:
        code_info = redis_store.get(EMAIL_RESET_PASSWORD_CACHE_KEY_PREFIX + key)
        if code_info is None or pickle.loads(code_info)['code'] != verify_code:
            raise Exception("invalid verify code")

    if not helpers.check_password_format(new_password):
        raise Exception("password format error")
    if helpers.check_password(new_password, user.password):
        raise Exception("can't use old password")
    password_crypted = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
    user.password = password_crypted

    if blocklink_address is not None and len(blocklink_address) > 0:
        if not helpers.is_valid_blocklink_address(blocklink_address):
            raise Exception("Invalid blocklink address format")
        if user.blocklink_address != blocklink_address:
            user.blocklink_address = blocklink_address

    user.updated_at = datetime.utcnow()
    db.session.add(user)
    db.session.commit()
    return user.to_print_json()


@jsonrpc.method('App.login(loginname=str,password=str,verify_code=str)')
@allow_cross_domain
def login(loginname, password, verify_code):
    if loginname is None or len(loginname) < 1:
        raise Exception("loginname can't be empty")
    # TODO; picture verify code check if this session request too many times
    user = User.query.filter_by(email=loginname).first()
    if user is None:
        raise Exception("user not found")
    if password is None or len(password) < 1:
        raise Exception("password can't be empty")
    if not helpers.check_password(password.encode('utf8'), user.password):
        raise Exception("Invalid username or password")
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
        raise Exception("invalid email format")
    if email is None or len(email) < 1:
        raise Exception("email can't be empty")
    if password is None or len(password) < 6:
        raise Exception("password can't be empty or less than 6 characters")
    user = User.query.filter_by(email=email).first()
    if user is not None:
        raise Exception("user with email %s existed" % email)
    if mobile is not None and len(mobile) > 30:
        raise Exception("mobile too long")

    if app.config['NEED_CAPTCHA']:
        email_code_info = redis_store.get(EMAIL_VERIFY_CODE_CACHE_KEY_PREFIX + email_code_key)
        if email_code_info is None or pickle.loads(email_code_info)['code'] != email_verify_code:
            raise Exception("invalid email verify code")

    if blocklink_address is not None and not helpers.is_valid_blocklink_address(blocklink_address):
        raise Exception("blocklink address %s format error" % blocklink_address)
    eth_account = helpers.generate_eth_account()
    encrypt_password = app.config['ETH_ENCRYPT_PASSWORD']
    password_crypted = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
    user = User(email=email, password=password_crypted, mobile=mobile, eth_address=None,
                blocklink_address=blocklink_address, family_name=family_name, given_name=given_name)
    user.eth_address = eth_account.address.lower()
    db.session.add(user)
    account = EthAccount(eth_account.address.lower(),
                         helpers.encrypt_eth_privatekey(eth_account.privateKey.hex(), encrypt_password))
    assert helpers.decrypt_eth_privatekey(account.encrypted_private_key,
                                          encrypt_password) == eth_account.privateKey.hex()
    db.session.add(account)
    db.session.commit()
    # TODO: daily backup eth address/privatekeys to private admin email
    return user.to_print_json()
