# coding: utf8
from __future__ import print_function
from app import db
from datetime import datetime
from sqlalchemy.sql import func
import time


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(30), nullable=True)
    family_name = db.Column(db.String(10), nullable=True)
    given_name = db.Column(db.String(10), nullable=True)
    eth_address = db.Column(db.String(100), nullable=True)
    blocklink_address = db.Column(db.String(100), nullable=True)
    unpayed_balance = db.Column(db.String(100), nullable=False, default='0')
    payed_balance = db.Column(db.String(100), nullable=False, default='0')
    disabled = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=func.now(), nullable=False)
    updated_at = db.Column(db.TIMESTAMP, server_default=func.now(), nullable=False)

    def __init__(self, email, password, mobile, eth_address, blocklink_address, family_name, given_name):
        self.email = email
        self.password = password
        self.mobile = mobile
        self.eth_address = eth_address
        self.blocklink_address = blocklink_address
        self.family_name = family_name
        self.given_name = given_name
        self.disabled = False
        self.is_admin = False
        self.created_at = None
        self.updated_at = None

    def __repr__(self):
        return '<User %r>' % self.email

    def to_print_json(self):
        return {
            'id': self.id,
            'email': self.email,
            'mobile': self.mobile,
            'eth_address': self.eth_address,
            'blocklink_address': self.blocklink_address,
            'family_name': self.family_name,
            'given_name': self.given_name,
            'unpayed_balance': str(self.unpayed_balance),
            'payed_balance': str(self.payed_balance),
            'disabled': self.disabled,
            'is_admin': self.is_admin,
            'created_at': time.mktime(self.created_at.utctimetuple()),
            'updated_at': time.mktime(self.updated_at.utctimetuple()),
        }


class EthAccount(db.Model):
    __tablename__ = 'eth_account'
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(100), nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=func.now(), nullable=False)
    updated_at = db.Column(db.TIMESTAMP, server_default=func.now(), nullable=False)

    def __init__(self, address, encrypted_private_key):
        self.address = address
        self.encrypted_private_key = encrypted_private_key

    def __repr__(self):
        return '<EthAccount %d>' % self.id


class EthTokenDepositOrder(db.Model):
    __tablename__ = 'eth_token_deposit_order'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)  # 充值时to_address对应的用户
    from_address = db.Column(db.String(100), nullable=False)
    to_address = db.Column(db.String(100), nullable=False)
    token_amount = db.Column(db.String(100), nullable=False)
    token_precision = db.Column(db.Integer, nullable=False)
    trx_id = db.Column(db.String(255), nullable=False)
    trx_time = db.Column(db.DateTime, nullable=False)
    token_symbol = db.Column(db.String(20), nullable=False)
    block_height = db.Column(db.Integer, nullable=False)
    token_contract_address = db.Column(db.String(100), nullable=False)
    trx_receipt_status = db.Column(db.String(20), nullable=True)

    blocklink_coin_sent = db.Column(db.Boolean, default=False, nullable=False)
    blocklink_coin_sent_trx_id = db.Column(db.String(100), nullable=True)
    sent_blocklink_coin_admin_user_id = db.Column(db.Integer, nullable=True)
    review_lock_by_user_id = db.Column(db.Integer, nullable=True)  # 被某个审核人员锁定的审核人员用户id
    review_state = db.Column(db.Boolean, default=None, nullable=True)  # 审核状态, None: 未处理, False 审核失败, True: 审核通过
    review_message = db.Column(db.Text, nullable=True)  # 审核备注消息
    created_at = db.Column(db.TIMESTAMP, server_default=func.now(), nullable=False)
    updated_at = db.Column(db.TIMESTAMP, server_default=func.now(), nullable=False)

    def __init__(self, from_address, to_address, token_amount, token_precision, trx_id, trx_time, token_symbol, block_height, token_contract_address, trx_receipt_status, user_id):
        self.from_address = from_address
        self.to_address = to_address
        self.token_amount = token_amount
        self.token_precision = token_precision
        self.trx_id = trx_id
        self.trx_time = trx_time
        self.token_symbol = token_symbol
        self.block_height = block_height
        self.token_contract_address = token_contract_address
        self.trx_receipt_status = trx_receipt_status
        self.user_id = user_id
        self.blocklink_coin_sent = False
        self.review_state = None
        self.review_message = None

    def __repr__(self):
        return '<EthTokenDepositOrder %d>' % self.id

    def to_dict(self):
        d = {c.name: getattr(self, c.name, None) for c in self.__table__.columns}
        d['created_at'] = time.mktime(self.created_at.utctimetuple())
        d['updated_at'] = time.mktime(self.updated_at.utctimetuple())
        return d
