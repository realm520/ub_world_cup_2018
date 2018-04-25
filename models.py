from __future__ import print_function
from app import db
from datetime import datetime
from sqlalchemy.sql import func


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(30), nullable=True)
    family_name = db.Column(db.String(10), nullable=True)
    given_name = db.Column(db.String(10), nullable=True)
    eth_address = db.Column(db.String(100), nullable=True)
    blocklink_address = db.Column(db.String(100), nullable=True)
    disabled = db.Column(db.Boolean, default=False, nullable=False)
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
            'disabled': self.disabled,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }

class EthAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(100), nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=func.now(), nullable=False)
    updated_at = db.Column(db.TIMESTAMP, server_default=func.now(), nullable=False)

    def __init__(self, address, encrypted_private_key):
        self.address = address
        self.encrypted_private_key = encrypted_private_key

    def __repr__(self):
        return '<EthAccount %d' % self.id