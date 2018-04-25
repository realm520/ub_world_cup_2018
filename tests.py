from __future__ import print_function
import os
import base64
from flask_jsonrpc.proxy import ServiceProxy
import captcha_helpers
import app
import helpers

os.environ['ETH_ENCRYPT_PASSWORD'] = '123456'

server = ServiceProxy('http://localhost:5000/api')

res = captcha_helpers.generate_verify_image(save_img=False)
print(res)
print(base64.b64encode(res[0].getvalue()).decode('utf8'))


helpers.send_email('zhouwei@blocklinker.com', '这是一个测试邮件', 'this is a test message 测试测试')
exit(0)

email1 = 'test2@blocklink.com'
registered_user = server.App.register(email1, '123456', None, None, '习', '大大', None, None, None, None)
print(registered_user)

res = server.App.login(email1, '123456', 'abcd')
print(res)
user = res['result']
assert user['email'] == email1

server.headers['X-TOKEN'] = user['auth_token']

res = server.App.viewProfile()
print(res)
user = res['result']
assert user['email'] == email1

res = server.App.requestEmailVerifyCode(email1)
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