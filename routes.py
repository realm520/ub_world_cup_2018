from __future__ import print_function
from flask import request, session
from flask_cors import CORS, cross_origin
from app import app, db, jsonrpc, redis_store
from models import User, EthAccount
import bcrypt
import helpers
import uuid
import base64
import json
import pickle
from helpers import allow_cross_domain
from functools import wraps
from datetime import datetime
import captcha_helpers

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

# TODO: query_order_history

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
    return user_json


@jsonrpc.method('App.changeBlocklinkAddress(address=str,verify_code=str)')
@allow_cross_domain
@check_auth
def change_blocklink_address(address, verify_code):
    user_json = session['user']

    token = request.headers.get(X_TOKEN_HEADER_KEY, None)
    key = token
    info = redis_store.get(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + key, None)
    if info is None or info['code'] is not verify_code:
        raise Exception('invalid verify code')

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


@jsonrpc.method('App.requestEmailVerifyCode(email=str)')
@allow_cross_domain
def request_email_verify_code(email):
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
    helpers.send_email(email, 'Reset Password', "Your verification code is %s" % code)
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
    redis_store.expire(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + key, 3*60)
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
    info = redis_store.get(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + key, None)
    if info is None:
        raise Exception('invalid captcha code')
    info = pickle.loads(info)
    if info['code'] is not code:
        raise Exception("invalid verify code")
    return True


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
    redis_store.expire(EMAIL_RESET_PASSWORD_CACHE_KEY_PREFIX + key, 5*60)
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
    code_info = redis_store.get(EMAIL_RESET_PASSWORD_CACHE_KEY_PREFIX + key)
    if code_info is None or pickle.loads(code_info)['code'] is not verify_code:
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


@jsonrpc.method('App.login(username=str,password=str,verify_code=str)')
@allow_cross_domain
def login(loginname, password, verify_code):
    if loginname is None or len(loginname) < 1:
        raise Exception("loginname can't be empty")
    # TODO; picture verify code check if this session request too many times
    user = User.query.filter_by(email=loginname).first()
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
    'App.register(email=str,password=str,blocklink_address=str,mobile=str,family_name=str,given_name=str,email_verify_code=str,picture_verify_code=str,email_code_key=str,picture_code_key=str)')
@allow_cross_domain
def register(email, password, blocklink_address, mobile, family_name, given_name, email_verify_code, picture_verify_code, email_code_key, picture_code_key):
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
    email_code_info = redis_store.get(EMAIL_VERIFY_CODE_CACHE_KEY_PREFIX + email_code_key)
    if email_code_info is None or pickle.loads(email_code_info)['code'] is not email_verify_code:
        raise Exception("invalid email verify code")
    picture_code_info = redis_store.get(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + email_code_key)
    if picture_code_info is None or pickle.loads(picture_code_info)['code'] is not picture_verify_code:
        raise Exception("invalid picture verify code")
    if not helpers.is_valid_blocklink_address(blocklink_address):
        raise Exception("blocklink address %s format error" % blocklink_address)
    eth_account = helpers.generate_eth_account()
    encrypt_password = app.config['ETH_ENCRYPT_PASSWORD']
    password_crypted = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
    user = User(email=email, password=password_crypted, mobile=mobile, eth_address=None,
                blocklink_address=blocklink_address, family_name=family_name, given_name=given_name)
    user.eth_address = eth_account.address
    db.session.add(user)
    account = EthAccount(eth_account.address, helpers.encrypt_eth_privatekey(eth_account.privateKey.hex(), encrypt_password))
    print(eth_account.address, eth_account.privateKey.hex(),
          helpers.decrypt_eth_privatekey(account.encrypted_private_key, encrypt_password))
    assert helpers.decrypt_eth_privatekey(account.encrypted_private_key, encrypt_password) == eth_account.privateKey.hex()
    db.session.add(account)
    db.session.commit()
    # TODO: daily backup eth address/privatekeys to private admin email
    return user.to_print_json()
