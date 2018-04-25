from __future__ import print_function
from flask import request, session
from app import app, db, jsonrpc
from models import User
import bcrypt
import helpers
from helpers import allow_cross_domain
from functools import wraps
from datetime import datetime


@app.route('/')
def hello_world():
    return 'Hello World!'


# TODO: query_order_history

def check_auth(f):
    @wraps(f)
    def _f(*args, **kwargs):
        try:
            if session.get('user', None) is not None:
                return f(*args, **kwargs)
            token = request.headers.get('X-TOKEN', None)
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


@allow_cross_domain
@jsonrpc.method('App.viewProfile()')
@check_auth
def view_profile():
    """API to view current user profile"""
    user_json = session['user']
    return user_json


@allow_cross_domain
@jsonrpc.method('App.changeBlocklinkAddress(address=str,verify_code=str)')
@check_auth
def change_blocklink_address(address, verify_code):
    """TODO"""
    user_json = session['user']
    # TODO: verify picture code
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


@allow_cross_domain
@jsonrpc.method('App.requestEmailVerifyCode(email=str)')
def request_email_verify_code(email):
    """TODO"""
    return True


@allow_cross_domain
@jsonrpc.method('App.requestPictureVerifyCode()')
def request_picture_verify_code():
    """TODO"""
    return "http://image.baidu.com/search/detail?ct=503316480&z=undefined&tn=baiduimagedetail&ipn=d&word=%E7%BE%8E%E5%9B%BE&step_word=&ie=utf-8&in=&cl=2&lm=-1&st=undefined&cs=2597352651,1038481775&os=1675601110,1384424370&simid=3454420665,391216152&pn=0&rn=1&di=141511965320&ln=1985&fr=&fmq=1524622650233_R&fm=&ic=undefined&s=undefined&se=&sme=&tab=0&width=undefined&height=undefined&face=undefined&is=0,0&istype=0&ist=&jit=&bdtype=0&spn=0&pi=0&gsm=0&objurl=http%3A%2F%2Ftupian.aladd.net%2F2015%2F9%2F1151.jpg&rpstart=0&rpnum=0&adpicid=0"


@allow_cross_domain
@jsonrpc.method('App.requestResetPassword(email=str)')
def request_reset_password(email):
    """TODO"""
    return True


@allow_cross_domain
@jsonrpc.method('App.resetPassword(email=str,new_password=str,verify_code=str)')
def reset_password(email, new_password, verify_code):
    user = User.query.filter_by(email=email).first()
    if user is None:
        raise Exception("Can't find user %s" % email)
    # TODO: check verify_code
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


@allow_cross_domain
@jsonrpc.method('App.login(username=str,password=str,verify_code=str)')
def login(loginname, password, verify_code):
    if loginname is None or len(loginname) < 1:
        raise Exception("loginname can't be empty")
    # TODO; picture verify code check
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


@allow_cross_domain
@jsonrpc.method('App.register(email=str,password=str,blocklink_address=str,mobile=str,verify_code=str)')
def register(email, password, blocklink_address, mobile, verify_code):
    if email is None or len(email) < 1:
        raise Exception("email can't be empty")
    if password is None or len(password) < 6:
        raise Exception("password can't be empty or less than 6 characters")
    user = User.query.filter_by(email=email).first()
    if user is not None:
        raise Exception("user with email %s existed" % email)
    if mobile is not None and len(mobile) > 30:
        raise Exception("mobile too long")
    # TODO: check email, picture verify code
    if not helpers.is_valid_blocklink_address(blocklink_address):
        raise Exception("blocklink address %s format error" % blocklink_address)
    password_crypted = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
    user = User(email=email, password=password_crypted, mobile=mobile, eth_address=None,
                blocklink_address=blocklink_address)
    db.session.add(user)
    db.session.commit()
    # TODO: generate eth address for user async. need save encrypted eth_address/private_keys to db and daily backup to private admin email
    return user.to_print_json()
