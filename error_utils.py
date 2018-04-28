# coding: utf8\
from flask_jsonrpc.exceptions import Error

class AutoTokenNotFoundError(Error):
    def __init__(self):
        self.code = 10001
        self.message = "auth token not found"
class UserNotFoundByAuthTokenError(Error):
    def __init__(self, token):
        self.code = 10002
        self.message = "user not found by auth token: %s" % token

class OtherError(Error):
    def __init__(self, message, code=10003):
        self.code = code
        self.message = message

class PermissionDeniedError(Error):
    def __init__(self):
        self.code = 10004
        self.message = "you have not enough permissions to visit this api"

class AuthTokenExpiredError(Error):
    def __init__(self):
        self.code = 10005
        self.message = 'Signature expired. Please log in again.'

class AuthTokenInvalidError(Error):
    def __init__(self):
        self.code = 10006
        self.message = 'Invalid token. Please log in again.'


class EmailFormatError(Error):
    def __init__(self):
        self.code = 10007
        self.message = "email format invalid"

class PasswordFormatError(Error):
    def __init__(self):
        self.code = 10008
        self.message = "password can't be empty or less than 6 characters"

class UserWithEmailExistedError(Error):
    def __init__(self, email):
        self.code = 10009
        self.message = "user with email %s existed" % email

class InvalidEmailVerifyCodeError(Error):
    def __init__(self):
        self.code = 10010
        self.message = "invalid email verify code"

class InvalidMobilePhoneFormatError(Error):
    def __init__(self):
        self.code = 10011
        self.message = "invalid mobile phone format"

class InvalidUsernameOrPasswordError(Error):
    def __init__(self):
        self.code = 10012
        self.message = "invalid username or password"

class InvalidPictureVerifyCodeError(Error):
    def __init__(self):
        self.code = 10013
        self.message = "invalid picture verify code"



class DepositOrderNotFoundError(Error):
    def __init__(self):
        self.code = 20001
        self.message = "Can't find this deposit order"

class DepositOrderProcessedBeforeError(Error):
    def __init__(self):
        self.code = 20002
        self.message = "this deposit order processed before"

class DepositOrderLockedError(Error):
    def __init__(self):
        self.code = 20003
        self.message = "this deposit order locked by other user"

class InvalidBlocklinkAddressFormatError(Error):
    def __init__(self, blocklink_address):
        self.code = 20004
        self.message = "blocklink address %s format error" % str(blocklink_address)

class UserNotFoundError(Error):
    def __init__(self):
        self.code = 20005
        self.message = "Can't find this user"

class BlocklinkTransactionIdUsedError(Error):
    def __init__(self):
        self.code = 20006
        self.message = "this blocklink transaction id used before in this service"

class DepositOrderNotReferToUserError(Error):
    def __init__(self):
        self.code = 20007
        self.message = "this deposit order not refer to a user"

class BlocklinkTransactionAmountNotEnoughError(Error):
    def __init__(self):
        self.code = 20008
        self.message = "this blocklink transaction's amount not enough"