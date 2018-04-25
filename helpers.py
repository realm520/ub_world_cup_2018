from __future__ import print_function
from flask import make_response
from functools import wraps
import jwt
import datetime
import bcrypt
from app import app


def allow_cross_domain(fun):
    @wraps(fun)
    def wrapper_fun(*args, **kwargs):
        res = fun(*args, **kwargs)
        rst = make_response(res)
        rst.headers['Access-Control-Allow-Origin'] = '*'
        rst.headers['Access-Control-Allow-Methods'] = 'PUT,GET,POST,DELETE'
        allow_headers = "Referer,Accept,Origin,User-Agent"
        rst.headers['Access-Control-Allow-Headers'] = allow_headers
        return rst

    return wrapper_fun


def is_valid_blocklink_address(addr):
    # TODO
    return True


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
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
