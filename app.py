#!/bin/env python3
from __future__ import print_function
from flask import Flask, make_response
from flask_cors import cross_origin
from flask_jsonrpc import JSONRPC
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', True)


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
db = SQLAlchemy(app)

import routes

try:
    db.create_all()
except Exception as e:
    print(e)
    pass

if __name__ == '__main__':
    app.run(port=5000, host='0.0.0.0', debug=True)
