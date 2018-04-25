#!/bin/env python3
from __future__ import print_function
from flask import Flask
from flask_jsonrpc import JSONRPC
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', True)
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
    app.run(port=5000, debug=True)
