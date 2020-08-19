class SendMsgMaxError(RuntimeError):
    """发送短信到达最大值"""
    code = 90001


class GlobalTimeoutError(TimeoutError):
    """全局业务超时"""
    code = 90001


class SendMsgFaultError(TimeoutError):
    """触发运营商反扒机制"""
    code = 90003


class UserTerminationError(PermissionError):
    """
    因为用户操作导致业务无法进行
    """
    code = 90004


class UserOperaFaultError(PermissionError):
    """用户操作失误"""
    code = 90005


class ChangeProxyTerminationError(PermissionError):
    code = 90009


class ReLoginWorkFlow(RuntimeError):
    """重登"""
    code = 90006


class ReRetryWorkFlow(RuntimeError):
    """重试"""
    code = 90008


class ReVerifyWorkFlow(RuntimeError):
    """二次验证重新登录"""
    code = 90007

    def __init__(self, **kwargs):
        self.carry = kwargs


class ReVerifyError(RuntimeError):
    """二次验证错误"""
    code = 90012

    def __init__(self, **kwargs):
        self.carry = kwargs


class CatchFault(RuntimeError):
    """获取失败，导致的错误"""
    code = 90008


class ValidError(KeyError):
    code = 90009


class SkipError(KeyError):
    code = 90009


class ContinueData(KeyError):
    code = 90011


class DAQTerminationError(KeyError):
    code = 90010
