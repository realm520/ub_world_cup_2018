# coding: utf8
from __future__ import print_function
from flask import request
import flask_jsonrpc
from functools import wraps
import jwt
import datetime
import bcrypt
import base64
import random
import hashlib
import binascii
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from Crypto import Random
from Crypto.Cipher import AES
import email_validator
from app import app
import eth_account
import config

def safeunicode(obj, encoding='utf-8'):
    r"""
    Converts any given object to unicode string.
        >>> safeunicode('hello')
        u'hello'
        >>> safeunicode(2)
        u'2'
        >>> safeunicode('\xe1\x88\xb4')
        u'\u1234'
    """
    t = type(obj)
    if t is str:
        return obj
    elif t is bytes:
        return obj.decode(encoding, 'ignore')
    elif t in [int, float, bool]:
        return str(obj)
    elif hasattr(obj, '__unicode__') or isinstance(obj, str):
        try:
            return str(obj)
        except Exception as e:
            return u""
    else:
        return str(obj).decode(encoding, 'ignore')

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = pad(raw).encode('utf8')
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:])).decode('utf8')


def allow_cross_domain(fun):
    @wraps(fun)
    def wrapper_fun(*args, **kwargs):
        res = fun(*args, **kwargs)
        rst = flask_jsonrpc.make_response(res)
        rst.headers['Access-Control-Allow-Origin'] = '*'
        rst.headers['Access-Control-Allow-Methods'] = 'PUT,GET,POST,DELETE,OPTIONS'
        allow_headers = config.ALLOWED_CROSS_ORIGIN_HEADERS
        rst.headers['Access-Control-Allow-Headers'] = allow_headers
        return rst

    return wrapper_fun


def is_valid_blocklink_address(addr):
    # TODO
    if addr is None or len(addr) < 20 or len(addr) > 40:
        return False
    return True


def is_valid_blocklink_trx_id(trx_id):
    # TODO
    if trx_id is None or len(trx_id) < 20 or len(trx_id) > 60:
        return False
    return True


def is_blocklink_trx_amount_valid_for_deposit(trx_id, to_address, amount):
    """判断blocklink链上交易id是否是转给to_address地址并且金额不少于amount * 0.99, amount type is Decimal"""
    return True  # TODO: 去blocklink链上或者区块浏览器中查找


def is_valid_email_format(email):
    if email is None or len(email) < 1:
        return False
    try:
        v = email_validator.validate_email(email)
        if email != v['email']:
            return False
        return True
    except email_validator.EmailNotValidError as _:
        return False


def check_password_format(password):
    if password is None or len(password) < 6 or len(password) > 40:
        return False
    return True


def check_password(password, hashed_password):
    if isinstance(password, str):
        password = password.encode('utf8')
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf8')
    return bcrypt.checkpw(password, hashed_password)


def encode_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, hours=1),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )
    except Exception as e:
        return e


def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :throws jwt.ExpiredSignatureError or jwt.InvalidTokenError
    :return: integer|string
    """
    payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
    return payload['sub']


def generate_captcha_code(n=6):
    digits = '0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjklmnpqrstuvwxyz'
    ss = ''
    for i in range(n):
        idx = random.randint(0, len(digits) - 1)
        ss += digits[idx]
    return ss


def send_email(to_address, subject, content):
    """send email task"""
    receipent = [to_address]
    try:
        message = MIMEText(content, 'plain', 'utf-8')
        message['From'] = app.config['SMTP_SENDER']
        print(to_address, subject, content)
        message['To'] = to_address
        message['Subject'] = subject

        smtpObj = smtplib.SMTP(app.config['SMTP_HOST'], app.config['SMTP_PORT'])
        smtpObj.login(app.config['SMTP_LOGIN'], app.config['SMTP_PASSWORD'])
        smtpObj.sendmail(app.config['SMTP_SENDER'], receipent, message.as_string())
        return True
    except smtplib.SMTPException as e:
        print(e)
        return False


def make_paginator_response(offset, limit, total, items):
    return {
        'offset': offset,
        'limit': limit,
        'total': total,
        'items': items,
    }