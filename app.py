#!/bin/env python3
from __future__ import print_function
from flask import Flask, make_response
from flask_cors import cross_origin
from flask_jsonrpc import JSONRPC
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
from celery import Celery
from datetime import timedelta
import os
import config
from logging_config import logger

config_model = 'development'
if os.environ.get('production', None) is not None:
    config_model = 'production'
elif os.environ.get('testing', None) is not None:
    config_model = 'testing'

logger.info('current config model is %s' % config_model)

app = Flask(__name__)
app.config.from_object(config.config[config_model])

redis_store = FlaskRedis(app)


@cross_origin
@app.route('/api', methods=['OPTIONS'])
def options_api():
    rst = make_response('')
    rst.headers['Access-Control-Allow-Origin'] = '*'
    rst.headers['Access-Control-Allow-Methods'] = 'PUT,GET,POST,DELETE,OPTIONS'
    allow_headers = config.ALLOWED_CROSS_ORIGIN_HEADERS
    rst.headers['Access-Control-Allow-Headers'] = allow_headers
    return rst


jsonrpc = JSONRPC(app, '/api', enable_web_browsable_api=True)

if len(app.config['ETH_ENCRYPT_PASSWORD']) > 16:
    raise Exception("ETH_ENCRYPT_PASSWORD too long")

db = SQLAlchemy(app)


def make_celery(app):
    celery = Celery(app.import_name, broker=app.config['CELERY_BROKER_URL'],
                    backend=app.config['CELERY_RESULT_BACKEND'])
    celery.conf.update(app.config)
    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask
    return celery


celery = make_celery(app)

import routes

try:
    db.create_all()
except Exception as e:
    logger.error("init db error", e)
    pass

if __name__ == '__main__':
    app.run(port=5000, host='0.0.0.0', debug=True)
