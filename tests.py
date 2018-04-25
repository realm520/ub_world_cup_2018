from __future__ import print_function
from flask_jsonrpc.proxy import ServiceProxy

server = ServiceProxy('http://localhost:5000/api')

email1 = 'test1@blocklink.com'
registered_user = server.App.register(email1, '123456', None, None, '习', '大大', None)
print(registered_user)

res = server.App.login('test1@blocklink.com', '123456', 'abcd')
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
assert res['result'] is True

res = server.App.requestPictureVerifyCode()
print(res)
assert isinstance(res['result'], str)

res = server.App.requestResetPassword(email1)
print(res)
assert res['result'] is True

res = server.App.resetPassword(email1, '111111', 'abcdef')
print(res)
assert res['result']['email'] == email1

res = server.App.login('test1@blocklink.com', '111111', 'abcd')
print(res)
user = res['result']
assert user['email'] == email1

res = server.App.resetPassword(email1, '123456', 'abcdef')
print(res)
assert res['result']['email'] == email1