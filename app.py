#!/bin/env python3
from __future__ import print_function
from flask import Flask, make_response
from flask_cors import cross_origin
from flask_jsonrpc import JSONRPC
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
import os

app = Flask(__name__)
app.config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', True)

REDIS_URL = "redis://:@localhost:6379/0"
redis_store = FlaskRedis(app)

@cross_origin
@app.route('/api', methods=['OPTIONS'])
def options_api():
    rst = make_response('')
    rst.headers['Access-Control-Allow-Origin'] = '*'
    rst.headers['Access-Control-Allow-Methods'] = 'PUT,GET,POST,DELETE,OPTIONS'
    allow_headers = "Referer,Accept,Origin,User-Agent,Content-Type"
    rst.headers['Access-Control-Allow-Headers'] = allow_headers
    return rst

jsonrpc = JSONRPC(app, '/api', enable_web_browsable_api=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./test.db'
app.config['SECRET_KEY'] = os.urandom(24)

# if os.getenv('ETH_ENCRYPT_PASSWORD', None) is None: # FIXME
#     raise Exception("Need set environment ETH_ENCRYPT_PASSWORD")
app.config['ETH_ENCRYPT_PASSWORD'] = os.getenv('ETH_ENCRYPT_PASSWORD', '123456')  # FIXME
if len(app.config['ETH_ENCRYPT_PASSWORD']) > 16:
    raise Exception("ETH_ENCRYPT_PASSWORD too long")

db = SQLAlchemy(app)

import routes

try:
    db.create_all()
except Exception as e:
    print(e)
    pass

if __name__ == '__main__':
    app.run(port=5000, host='0.0.0.0', debug=True)
