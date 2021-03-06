# coding: utf8
from __future__ import print_function
from flask import request
from flask_cors import CORS, cross_origin
from app import app, db, jsonrpc, redis_store
from models import TTeam, TSchedule, TStake
import base64
import os
import uuid
import json
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
# import celery_task
from logging_config import logger
import error_utils

CORS(app)


@app.teardown_request
def teardown_request(exception):
    if exception:
        db.session.rollback()
    db.session.remove()


@jsonrpc.method('App.queryStakeHistory(address=str)')
@allow_cross_domain
def query_stake_history(address):
    """query stake history of one address"""
    db.session.commit()
    if address is None or not isinstance(address, str):
        raise InvalidParamsError()
    stakes = TStake.query.filter(TStake.address == address)
    details = []
    #TODO, total bingo stakes need be updated.
    total_bingo_stakes = 1000
    user_deposit = 0.0
    user_bingo_stakes = 0
    for s in stakes:
        record = {'address': s.address, 'item': s.item, 'state': s.state,
                  'time': time.strftime("%Y-%m-%d %H:%M:%S", s.time.utctimetuple())}
        if s.state == 1:
            user_bingo_stakes += s.count
            record['money'] = s.count * 100 / total_bingo_stakes
        else:
            record['money'] = 0
        if s.isAnybit == 0:
            record['deposit'] = round(float(s.count) / 10, 2)
        elif s.isAnybit == 1:
            record['deposit'] = round(float(s.count * 8 / 100), 2)
        user_deposit += record['deposit']
        record['awards'] = s.count
        record['txid'] = s.txid
        details.append(record)
    return {'deposit': round(user_deposit, 2), 'allawards': round(user_bingo_stakes * 100 / total_bingo_stakes, 2),
            'details': details }



@jsonrpc.method('App.queryStakeStat(stat_type=int,stake_type=int,limit=int)')
@allow_cross_domain
def query_stake_stat(stat_type, stake_type=None, limit=20):
    """query total stake statistics"""
    if stat_type is None or not isinstance(stat_type, int):
        raise InvalidParamsError()
    if limit is None or not isinstance(limit, int) or limit < 1:
        limit = 20
    if stat_type == 1:
        # stat by address and/or type
        if stake_type is None or not isinstance(stake_type, int):
            stakes = db.session.query(TStake.address, func.sum(TStake.count).label('address_count')). \
                group_by(TStake.address).order_by('address_count desc').limit(limit)
        else:
            stakes = db.session.query(TStake.address, func.sum(TStake.count).label('address_count')).\
                filter(TStake.type == stake_type).group_by(TStake.address).\
                order_by('address_count desc').limit(limit)
        item_name = "address"
    elif stat_type == 2:
        # stat by champion team
        stakes = db.session.query(TStake.item, func.sum(TStake.count).label('team_count')).\
            filter(TStake.type == 2).group_by(TStake.item).\
            order_by('team_count desc').limit(limit)
        item_name = "champion"
    elif stat_type == 3:
        # stat by scores
        stakes = db.session.query(TStake.item, func.sum(TStake.count).label('score_count')).\
            filter(TStake.type == 3).group_by(TStake.item).\
            order_by('score_count desc').limit(limit)
        item_name = "score"
    elif stat_type == 4:
        # stat by favourite team
        stakes = db.session.query(TStake.item, func.sum(TStake.count).label('team_count')).\
            filter(TStake.type == 4).group_by(TStake.item).\
            order_by('team_count desc').limit(limit)
        item_name = "team"

    data = []
    for s in stakes:
        data.append({item_name: s[0], "count": int(s[1])})
    return data


@jsonrpc.method('App.queryMatchResult(team=int)')
@allow_cross_domain
def query_match_result(team=None):
    if team is None or not isinstance(team, int):
        match = TSchedule.query.all()
    else:
        match = TSchedule.query.filter(or_(TSchedule.team_a==team, TSchedule.team_b==team))
    data = []
    for t in match:
        data.append(t.to_print_json())
    return data


@jsonrpc.method('App.queryTeamInfo(group=str)')
@allow_cross_domain
def query_team_info(group=1):
    if group is None or not isinstance(group, str) or len(group) > 1:
        team = TTeam.query.all()
    else:
        team = TTeam.query.filter(TTeam.group == group)
    data = []
    for t in team:
        data.append(t.to_print_json())
    return data


@jsonrpc.method('App.queryStakeMemo(stake_type=int, stake_item=int)')
@allow_cross_domain
def query_stake_memo(stake_type, stake_item):
    if stake_type != 2 or stake_item < 1 or stake_item > 32:
        raise InvalidParamsError()
    str_memo = str(stake_item) + ":2"
    return bytes.decode(base64.b64encode(str.encode(str_memo)))

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
