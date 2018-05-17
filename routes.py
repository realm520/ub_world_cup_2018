# coding: utf8
from __future__ import print_function
from flask import request
from flask_cors import CORS, cross_origin
from app import app, db, jsonrpc, redis_store
from models import TTeam, TSchedule, TStake
import bcrypt
import helpers
import uuid
import base64
import json
import pickle
import time
# import jwt
from flask_jsonrpc.exceptions import InvalidParamsError
from decimal import Decimal
from helpers import allow_cross_domain
from functools import wraps
from datetime import datetime
from sqlalchemy import or_
from sqlalchemy.sql import func
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


@jsonrpc.method('App.queryStakeHistory(address=str,limit=int,state=int)')
@allow_cross_domain
def query_stake_history(address, limit, state):
    """query stake history of one address"""
    if address is None or not isinstance(address, str):
        raise InvalidParamsError()
    if limit is None or limit < 1:
        limit = 20
    stakes = TStake.query.filter(TStake.address==address, TStake.state==state).limit(limit)

    return list(stakes)


@jsonrpc.method('App.queryStakeStat(stat_type=int,limit=int)')
@allow_cross_domain
def query_stake_history(stake_type, stat_type, limit):
    """query total stake statistics"""
    if stat_type is None or not isinstance(stat_type, int):
        raise InvalidParamsError()
    if limit is None or not isinstance(limit, int) or limit < 1:
        limit = 20
    if stat_type == 1:
        # stat by address and/or type
        if stake_type is None or not isinstance(stake_type, int):
            stakes = TStake.query(TStake.address, func.sum(TStake.count).label('address_count')). \
                group_by(TStake.address).order_by('address_count').limit(limit)
        else:
            stakes = TStake.query(TStake.address, func.sum(TStake.count).label('address_count')).\
                filter(TStake.type == stake_type).group_by(TStake.address).\
                order_by('address_count').limit(limit)
    elif stat_type == 2:
        # stat by favourite team
        stakes = TStake.query(TStake.item, func.sum(TStake.count).label('team_count')).\
            filter(TStake.type == 4).group_by(TStake.item).\
            order_by('team_count').limit(limit)
    elif stat_type == 2:
        # stat by scores
        stakes = TStake.query(TStake.item, func.sum(TStake.count).label('score_count')).\
            filter(TStake.type == 3).group_by(TStake.item).\
            order_by('score_count').limit(limit)

    return list(stakes)


@jsonrpc.method('App.queryMatchResult(id=int,team=str)')
@allow_cross_domain
def query_match_result(team):
    if team is None:
        match = TSchedule.query.all()
    else:
        match = TSchedule.query.filter(or_(TSchedule.team_a==team, TSchedule.team_b==team))
    return list(match)


@jsonrpc.method('App.queryTeamInfo()')
@allow_cross_domain
def query_team_info():
    team = TTeam.query.all()
    return list(team)


# PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX = 'PVC'
#
# @jsonrpc.method('App.requestPictureVerifyCode()')
# @allow_cross_domain
# def request_picture_verify_code():
#     """generate picture captcha image"""
#     stream, code = captcha_helpers.generate_verify_image(save_img=False)
#     img_base64 = base64.b64encode(stream.getvalue()).decode('utf8')
#     token = request.headers.get(X_TOKEN_HEADER_KEY, None)
#     # TODO: check too often
#     key = str(uuid.uuid4())
#     redis_store.set(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + key, pickle.dumps({
#         'code': code,
#         'time': datetime.utcnow(),
#     }))
#     redis_store.expire(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + key, 10 * 60)
#     return {
#         'img': img_base64,
#         'key': key,
#     }
#
#
# @jsonrpc.method('App.verifyPictureCode(key=str,code=str)')
# @allow_cross_domain
# def verify_picture_code(key, code):
#     # TODO: check too often
#     if key is None or code is None or len(key) < 1 or len(code) < 1:
#         raise InvalidParamsError()
#     if app.config['NEED_CAPTCHA']:
#         info = redis_store.get(PICTURE_VERIFY_CODE_CACHE_KEY_PREFIX + key)
#         if info is None:
#             return False
#         info = pickle.loads(info)
#         if info['code'] != code:
#             return False
#     return True
#
#
# @jsonrpc.method('App.verifyAddressFormat(address=str)')
# @allow_cross_domain
# def verify_address_format(address):
#     return helpers.is_valid_blocklink_address(address)
#
#
# @jsonrpc.method('App.resetPassword(email=str,new_password=str,verify_code=str,key=str)')
# @allow_cross_domain
# def reset_password(email, new_password, verify_code, key):
#     user = User.query.filter_by(email=email).first()
#     if user is None:
#         raise error_utils.UserNotFoundError()
#     if app.config['NEED_CAPTCHA']:
#         code_info = redis_store.get(EMAIL_RESET_PASSWORD_CACHE_KEY_PREFIX + key)
#         if code_info is None or pickle.loads(code_info)['code'] != verify_code:
#             logger.error("receive verify code: %s, required is %s" % (verify_code, pickle.loads(code_info)['code'] if code_info else ''))
#             raise error_utils.InvalidEmailVerifyCodeError()
#
#     if not helpers.check_password_format(new_password):
#         raise error_utils.PasswordFormatError()
#     if helpers.check_password(new_password, user.password):
#         raise error_utils.OtherError("can't use old password")
#     password_crypted = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
#     user.password = password_crypted
#     user.updated_at = datetime.utcnow()
#     db.session.add(user)
#     db.session.commit()
#     return user.to_print_json()
#
