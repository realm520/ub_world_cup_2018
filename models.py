# coding: utf8
from __future__ import print_function
from app import db
from datetime import datetime
from sqlalchemy.sql import func
import time


class TTeam(db.Model):
    __tablename__ = 't_team'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(45), unique=True)
    name_en = db.Column(db.String(45), nullable=False)
    group = db.Column(db.String(1), nullable=True)
    point = db.Column(db.Integer, nullable=False, default=0)
    rank = db.Column(db.Integer, nullable=False, default=9)

    def __init__(self, id, name, name_en, group, point, rank):
        self.id = id
        self.name = name
        self.name_en = name_en
        self.group = group
        self.point = point
        self.rank = rank

    def __repr__(self):
        return '<Team %r>' % self.name_en

    def to_print_json(self):
        return {
            'id': self.id,
            'name': self.name,
            'name_en': self.name_en,
            'group': self.group,
            'point': self.point,
            'rank': self.rank,
        }


class TSchedule(db.Model):
    __tablename__ = 't_schedule'
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)
    team_a = db.Column(db.Integer, nullable=False)
    team_b = db.Column(db.Integer, nullable=False)
    city = db.Column(db.String(45), nullable=False)
    result = db.Column(db.Integer, nullable=False, default=-1)

    def __init__(self, id, start_time, team_a, team_b, city, result):
        self.id = id
        self.start_time = start_time
        self.team_a = team_a
        self.team_b = team_b
        self.city = city
        self.result = result


    def __repr__(self):
        return '<Schedule %d>' % self.id

    def to_print_json(self):
        return {
            'id': self.id,
            'start_time': time.strftime("%Y-%m-%d %H:%M:%S", self.start_time.utctimetuple()),
            'team_a': self.team_a,
            'team_b': self.team_b,
            'city': self.city,
            'result': self.result,
        }


class TStake(db.Model):
    __tablename__ = 't_stake'
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(40), nullable=False)
    count = db.Column(db.Integer, nullable=True)
    time = db.Column(db.DateTime, nullable=False)
    type = db.Column(db.Integer, nullable=True)
    item = db.Column(db.Integer, nullable=True)
    state = db.Column(db.Integer, nullable=True, default=0)
    txid = db.Column(db.String(128), nullable=False, default='')

    def __init__(self, address, count, time, type, item, state, txid):
        self.address = address
        self.count = count
        self.time = time
        self.type = type
        self.item = item
        self.state = state
        self.txid = txid

    def __repr__(self):
        return '<Stake %d>' % self.id

    def to_print_json(self):
        return {
            'id': self.id,
            'address': self.address,
            'time': time.strftime("%Y-%m-%d %H:%M:%S", self.time.utctimetuple()),
            'type': self.type,
            'item': self.item,
            'state': self.state,
            'txid': self.txid,
        }
