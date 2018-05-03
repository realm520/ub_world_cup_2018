# coding: utf8
from __future__ import print_function
import os
import base64
from flask_jsonrpc.proxy import ServiceProxy
import captcha_helpers
import app
import helpers
import eth_helpers
import celery_task
import unittest

encoded_privatekey = eth_helpers.encrypt_eth_privatekey('123456', '12345ssdlh'.encode('utf8'))
decoded_privatekey = eth_helpers.decrypt_eth_privatekey(encoded_privatekey, '12345ssdlh'.encode('utf8'))
print(encoded_privatekey, decoded_privatekey)
assert decoded_privatekey == '123456'


os.environ['ETH_ENCRYPT_PASSWORD'] = '123456'

server = ServiceProxy('http://localhost:5000/api')

res = captcha_helpers.generate_verify_image(save_img=False)
print(res)
print(base64.b64encode(res[0].getvalue()).decode('utf8'))


celery_task.direct_crawl_eth_token_deposits()
# exit(0)

# helpers.send_email('zhouwei@blocklinker.com', '这是一个测试邮件', 'this is a test message 测试测试')
# exit(0)

email1 = 'test1@blocklink.com'
registered_user = server.App.register(email1, '123456', None, None, '习', '大大', 'test', 'test')
print(registered_user)

res = server.App.login(email1, '123456', 'abcd')
print(res)
user = res['result']
assert user['email'] == email1

server.headers['X-TOKEN'] = user['auth_token']

res = server.App.myDepositHistory(None, None, None, True)
print("myDepositHistory", res)
# exit(0)

res = server.App.viewProfile()
print(res)
user = res['result']
assert user['email'] == email1

res = server.App.requestRegisterEmailVerifyCode(email1, 'test', 'test')
print(res)
assert isinstance(res['result']['key'], str)

res = server.App.requestPictureVerifyCode()
print(res)
assert isinstance(res['result']['img'], str) and isinstance(res['result']['key'], str)

res = server.App.requestResetPassword(email1)
print(res)
assert isinstance(res['result']['key'], str)

res = server.App.resetPassword(email1, '111111', 'abcdef', server.headers['X-TOKEN'])
print(res)
assert res['result']['email'] == email1

res = server.App.login(email1, '111111', 'abcd')
print(res)
user = res['result']
assert user['email'] == email1

res = server.App.resetPassword(email1, '123456', 'abcdef', server.headers['X-TOKEN'])
print(res)
assert res['result']['email'] == email1

res = server.App.requestPictureVerifyCode()
print(res)

res = server.App.myDepositHistory(None, None, None, True)
print(res)

res = server.App.usersDepositHistory(None, None, None, None, None, None, None, email1)
print(res)

res = server.App.listUsers(None, None, None)
print("listUsers:", res['result'])

res = server.App.listDepositEthAccounts(None, None, None)
print("listDepositEthAccounts:", res['result'])
