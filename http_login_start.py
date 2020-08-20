# -*- coding: utf-8 -*-
import base64
import hashlib
import json
import logging
import os
import pickle
import re
import sys
import time

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from redis import StrictRedis

requests.packages.urllib3.disable_warnings()
logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class ResultOutput(object):
    def __init__(self):
        self.code = 10000
        self.msg = u''

    def set_code(self, code):
        self.code = str(code)

    def set_msg(self, msg):
        self.msg = msg

    def done(self):
        sys.stdout.write('\0')
        code = self.code
        try:
            msg = self.msg.encode('utf-8')
        except Exception:
            msg = self.msg
        sys.stdout.write(json.dumps({'code': code, 'msg': msg}, ensure_ascii=False))
        sys.stdout.write('\n')
        exit()


result_output = ResultOutput()


class ChangeProxyTerminationError(SystemError):
    code = 90009


def now_ts_in_millis():
    return int(time.time() * 1000)


class MySession(requests.Session):
    def post(self, url, data=None, json=None, **kwargs):
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 5
        try:
            return super(MySession, self).post(url, data, json, **kwargs)
        except (requests.exceptions.ReadTimeout, requests.exceptions.Timeout):
            logger.debug(u'请求连接超时，重试一次. url: {}'.format(url))
            return super(MySession, self).post(url, data, json, **kwargs)


class HttpBasic(object):
    Request = requests.Request

    def __init__(self, *args, **kwargs):
        self._crawler_session = MySession()
        self._crawler_session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0',
            'Accept-Encoding': 'gzip',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Accept': 'text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, '
                      '*/*; q=0.01 '
        }
        self.verifyCode = ''
        self._crawler_session.verify = False

    def _quick_get_request(self, *args, **kwargs):
        return self._crawler_session.get(*args, **kwargs)

    def _quick_post_request(self, *args, **kwargs):
        return self._crawler_session.post(*args, **kwargs)

    def get_herders(self, req):
        referer = req.headers.get('Referer')
        if referer:
            origin = re.search(r'(.*?://.*?)/', referer, re.M | re.I)
            if origin:
                origin = origin.group()[:-1]
            else:
                origin = referer
            req.headers['Host'] = str(origin.split('//')[1])
            req.headers['Origin'] = str(origin)

    def call(self, req, timeout=None, proxies=None, allow_redirects=True, stream=None, verify=None, cert=None,
             json=None):
        # self.get_herders(req)
        if 'Cookie' not in req.headers:
            req.headers['Cookie'] = self.get_cookies()
        # 'Cookie': ';'.join([f'{cookie.name}={cookie.value}'for cookie in self._crawler_session.cookies])
        #  处理headers
        # req.headers['x-forwarded-for'] = '39.130.66.145'
        # req.headers['Proxy-Client-IP'] = '39.130.66.145'
        # req.headers['WL-Proxy-Client-IP'] = '39.130.66.145'
        # req.headers['X-Real-IP'] = '39.130.66.145'
        # req.headers['Proxy-Connection'] = 'keep-alive'

        prep = self._crawler_session.prepare_request(req)
        proxies = proxies or {}
        settings = self._crawler_session.merge_environment_settings(
            prep.url, proxies, stream, verify, cert
        )

        # Send the request.
        send_kwargs = {
            'timeout': timeout,
            'allow_redirects': allow_redirects,
        }
        send_kwargs.update(settings)
        resp = self._crawler_session.send(prep, **send_kwargs)
        return resp

    def get_cookies(self):
        return ';'.join(['{}={}'.format(cookie.name, cookie.value) for cookie in self._crawler_session.cookies])

    def easy_get(self, url, **headers):
        return self.call(self.Request(method='GET', url=url, headers=headers))

    def warning(self, msg, **kwargs):
        self.log(logging.WARNING, msg, **kwargs)

    def info(self, msg, **kwargs):
        self.log(logging.INFO, msg, **kwargs)

    def error(self, msg, **kwargs):
        self.log(logging.ERROR, msg, **kwargs)

    def debug(self, msg, **kwargs):
        self.log(logging.DEBUG, msg, **kwargs)

    def log(self, method, msg, **kwargs):
        sys.stdout.write(msg + '\n')


class HttpLoginCMCC(HttpBasic):
    """ 采用request的方式做移动抓取 """
    _INIT_HOME_URL = 'https://login.10086.cn/login.html?channelID=12034&backUrl=https%3A%2F%2Fshop.10086.cn%2Fi%2F' \
                     '%3Ff%3Dhome '
    _INIT_LOGIN_URL = 'https://login.10086.cn/needVerifyCode.htm?accountType=01&account={}&timestamp={}'
    _INIT_LOAD_SEND_FLAG = "https://login.10086.cn/loadSendflag.htm?timestamp={}"
    _INIT_CHK_NUMBER_ACTION = "https://login.10086.cn/chkNumberAction.action"
    _INIT_LOAD_TOKEN_ACTION = "https://login.10086.cn/loadToken.action"
    _INIT_SEND_RANDOM_CODE_ACTION = "https://login.10086.cn/sendRandomCodeAction.action"

    _LOGIN_CHECKOUT_LOGIN = "http://www1.10086.cn/web-Center/authCenter/checkUserLogin.do"

    def __init__(self, mobile, *args, **kwargs):
        super(HttpLoginCMCC, self).__init__(mobile, *args, **kwargs)
        self.mobile = mobile
        self.veri_time = 0
        self.login_time = 0
        self._crawler_session.headers = {
            'Accept-Language': 'zh-cn',
            'Accept-Encoding': 'gzip, deflate, br',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/81.0.4044.122 Safari/537.36',
        }
        self.default_headers = {
        }
        self.secret = "CM_201606"
        self.auth_channel_id = "12034"
        self.version = "1.0"
        self.channel_id = "0001"
        self.navigator = {
            "appName": "Netscape",
            "appVersion": '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/81.0.4044.122 Safari/537.36',
            "userAgent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                         'Chrome/81.0.4044.122 Safari/537.36 '
        }

    def formar_number(self, num, n):
        rv = str(num)
        length = len(rv)
        if length <= n:
            for i in range(0, n - length):
                rv = '0' + rv
        else:
            rv = rv[length - n: 2 * length - n]
        return rv

    def get_conversation_id(self, curtime, href=''):
        import time
        current = curtime / 1000
        timeArray = time.localtime(current)
        date_format = time.strftime("%Y%m%d%H%M%S", timeArray)
        milliseconds = str(current)
        # milliseconds = str(current).split('.')[1]
        # 根据当前时间毫秒数、url以及用户特定信息进行md5运算，产生随机数
        strSeed = ''.join([str(curtime), ",", href, ',', self.navigator['appName'], ',',
                           self.navigator['appVersion'], ',',
                           self.navigator['userAgent']])

        seed_md5 = hashlib.md5(strSeed.encode()).hexdigest()[25: 32]
        import execjs
        rnd = self.formar_number(execjs.compile("parseInt").call('parseInt', seed_md5, 16), 6)
        return ''.join([date_format,
                        milliseconds,
                        rnd])

    def get_digest(self, curtime, secret):
        strmd5 = hashlib.md5("{}{}".format(curtime, secret).encode()).hexdigest()
        return base64.b64encode(strmd5.encode()).decode()

    def check_user_login(self, referer, channel_id='12034'):
        timestamp = now_ts_in_millis()
        json_data = {
            "serviceName": "",
            "header": {
                "version": self.version,
                "timestamp": timestamp,
                "digest": self.get_digest(timestamp, self.secret),
                "conversationId": self.get_conversation_id(timestamp, referer)
            },
            "data": {
                "channelId": channel_id
            }
        }
        return self.call(self.Request(method='POST', url=self._LOGIN_CHECKOUT_LOGIN, headers={
            'Referer': referer,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept': '*/*',
            'Host': 'www1.10086.cn',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Cookie': self.get_cookies()
        }, data={'requestJson': json.dumps(json_data).replace(' ', '')}), allow_redirects=True)

    def need_verify_code(self, mobile, **kwargs):
        """
            初始化登陆窗体，设置 sendflag CITY_INFO Cookies
        :return:
        """
        # 判断是否以前已经登陆过。则获取verifyCode，检查是否需要发送短信
        self.verifyCode = ''
        self.easy_get(self._INIT_HOME_URL, Referer=self._INIT_HOME_URL)
        self.easy_get(self._INIT_LOAD_SEND_FLAG.format(now_ts_in_millis()), Referer=self._INIT_HOME_URL)
        resp = None
        if self.verifyCode:
            cur_headers = {
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': self._INIT_HOME_URL,
                'Cookie': 'verifyCode=' + self.verifyCode
            }
            resp = self.call(
                self.Request(method='GET', url=self._INIT_LOGIN_URL.format(self.mobile, now_ts_in_millis()),
                             headers=cur_headers))
        req = self.Request(method='POST', url=self._INIT_CHK_NUMBER_ACTION, data={"userName": mobile},
                           headers={'Referer': self._INIT_HOME_URL})
        self.call(req)
        if resp and '{"needVerifyCode":"0"}' == resp.text:
            return False
        return True

    def send_first_code(self, mobile, **kwargs):
        """第一个页面发送短信码"""
        cur_headers = {
            'Referer': self._INIT_HOME_URL,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': 'https://login.10086.cn'
        }
        req = self.Request(method='POST', url=self._INIT_LOAD_TOKEN_ACTION, data={'userName': mobile},
                           headers=cur_headers)
        resp = self.call(req)
        result = resp.json()['result']
        resp = self.easy_get(url=self._INIT_LOAD_SEND_FLAG.format(now_ts_in_millis()), Referer=self._INIT_HOME_URL)
        sendflag = resp.cookies.get('sendflag')
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': self._INIT_HOME_URL,
            'Xa-before': result,
            'Cookie': 'sendflag=' + sendflag
        }
        data = {
            'userName': mobile,
            'type': '01',
            'channelID': '12034'
        }
        req = self.Request(method='POST', url=self._INIT_SEND_RANDOM_CODE_ACTION, data=data, headers=headers)
        resp = self.call(req)
        text = resp.text
        if '0' in text:
            result_output.set_msg(u'短信发送成功')
            return True
        elif '1' in text:
            result_output.set_msg(u'短信发送失败,请一分钟后再试')
        elif '2' in text:
            result_output.set_msg(u'短信下发数已达上限,请明天再试')
        elif '3' in text:
            result_output.set_msg(u'短信发送过于频繁,请明天再试')
        elif '6' in text:
            result_output.set_msg(u'短信发送失败，请稍后再试')
        else:
            result_output.set_msg(u'短信发送失败,请重试')
        result_output.set_code(20002)
        return False

    def go_login_with_passwd(self, password, sms_code=''):
        """通过服务密码登陆"""
        rsa_pwd = self.__encryption_passwd(password)
        if self.verifyCode is None:
            self.verifyCode = ''
        resp = self.call(self.Request(method='POST',
                                      url="https://login.10086.cn/login.htm",
                                      data={
                                          'accountType': '01',
                                          'account': self.mobile,
                                          'password': rsa_pwd,
                                          'pwdType': '01',
                                          'smsPwd': sms_code,
                                          'inputCode': '',
                                          'backUrl': 'http://www.10086.cn/index/sh/index_210_210.html',
                                          'rememberMe': '0',
                                          'channelID': '12034',
                                          'loginMode': '01',
                                          'protocol': 'https:',
                                          'timestamp': now_ts_in_millis()
                                      },
                                      headers={
                                          'X-Requested-With': 'XMLHttpRequest',
                                          'Referer': self._INIT_HOME_URL,
                                          'Cookie': 'verifyCode=' + self.verifyCode,
                                          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                                          'Accept': 'application/json, text/javascript, */*; q=0.01'
                                      }))
        return resp

    def go_login_with_msg(self, sms_code):
        """通过短信密码登陆"""
        rsa_pwd = self.__encryption_passwd(sms_code)
        resp = self.call(self.Request(method='POST',
                                      url="https://login.10086.cn/login.htm",
                                      data={
                                          'accountType': '01',
                                          'account': self.mobile,
                                          'password': rsa_pwd,
                                          'pwdType': '02',
                                          'smsPwd': '',
                                          'inputCode': '',
                                          'backUrl': 'http://www.10086.cn/index/sh/index_210_210.html',
                                          'rememberMe': '0',
                                          'channelID': '12034',
                                          'loginMode': '01',
                                          'protocol': 'https:',
                                          'timestamp': now_ts_in_millis()
                                      },
                                      headers={
                                          'X-Requested-With': 'XMLHttpRequest',
                                          'Referer': self._INIT_HOME_URL,
                                          'Cookie': 'verifyCode=',
                                          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                                          'Accept': 'application/json, text/javascript, */*; q=0.01'
                                      }))
        return resp

    def go_login(self, sms_code=''):
        """ 登录方法 """
        # try:
        # 登录封装
        resp = self.go_login_with_msg(sms_code)
        jo = resp.json()
        if '0000' == jo['code']:
            # ok
            artifact = jo['artifact']
            assert_accept_url = jo['assertAcceptURL']
            resp = self.call(
                self.Request(method='GET',
                             url=assert_accept_url + '?backUrl=http%3A%2F%2Fwww.10086.cn%2Findex%2Ffj%2Findex_591_591.'
                                                     'html&&artifact=' + artifact + '&type=00',
                             headers={
                                 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,'
                                           'image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                                 'Upgrade-Insecure-Requests': '1',
                                 'Connection': 'keep-alive',
                                 'Sec-Fetch-Site': 'same-site',
                                 'Sec-Fetch-Mode': 'navigate',
                                 'Sec-Fetch-User': '?1',
                                 'Sec-Fetch-Dest': 'document',
                                 'Referer': 'https://login.10086.cn/login.html?channelID=12034&backUrl=http%3A'
                                            '%2F%2Fwww.10086.cn%2Findex%2Ffj%2Findex_591_591.html',
                             }
                             ), allow_redirects=False)
            if resp.status_code == 302:
                self.call(self.Request(method='GET',
                                       url=resp.next.url,
                                       headers={
                                           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,'
                                                     'image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                                           'Upgrade-Insecure-Requests': '1',
                                           'Connection': 'keep-alive',
                                       }
                                       ), allow_redirects=False)

            sso_check = "https://login.10086.cn/SSOCheck.action?channelID=12003&backUrl=https://shop.10086.cn/i/?f=home"
            self.easy_get(url=sso_check)
            home_url = 'https://shop.10086.cn/i/?welcome=' + str(now_ts_in_millis())
            self.easy_get(url=home_url)
            import time
            time.sleep(0.5)
            resp = self.check_user_login(home_url)
            json_obj = resp.json()
            retCode = json_obj['result']['response_code']
            if '0000' == retCode and json_obj['result']['data']['isLogin'] == 1:
                self._crawler_session.user_info_text = resp.text
                return True
            else:
                result_output.set_code(20002)
                result_output.set_msg(u'系统繁忙，请您稍后再做手机认证')
                return False
        elif '3011' == jo['code']:
            result_output.set_code(20002)
            result_output.set_msg(u'请在移动商城取消登录保护，链接https://login.10086.cn/protect/protect_web.htm，如有疑问，请咨询客服')
            return False
        else:
            err_msg = jo['desc']
            result_output.set_code(20002)
            result_output.set_msg(err_msg)
            return False
        # except Exception:
        # self._change_proxy()
        # self.error(msg='登录异常', row_data=resp.text)
        # err_msg = '系统繁忙，请您稍后再做手机认证'
        # return SignInResponseBuilder().step(self._FIRST_STEP).set_login_err(err_msg).build()

    def __encryption_passwd(self, k):
        rsa_publickey = '''-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsgDq4OqxuEisnk2F0EJF
    mw4xKa5IrcqEYHvqxPs2CHEg2kolhfWA2SjNuGAHxyDDE5MLtOvzuXjBx/5YJtc9
    zj2xR/0moesS+Vi/xtG1tkVaTCba+TV+Y5C61iyr3FGqr+KOD4/XECu0Xky1W9Zm
    maFADmZi7+6gO9wjgVpU9aLcBcw/loHOeJrCqjp7pA98hRJRY+MML8MK15mnC4eb
    ooOva+mJlstW6t/1lghR8WNV8cocxgcHHuXBxgns2MlACQbSdJ8c6Z3RQeRZBzyj
    fey6JCCfbEKouVrWIUuPphBL3OANfgp0B+QG31bapvePTfXU48TYK0M5kE+8Lgbb
    WQIDAQAB
    -----END PUBLIC KEY-----'''
        key = RSA.import_key(rsa_publickey)
        passwd = PKCS1_v1_5.new(key)
        text = base64.b64encode(passwd.encrypt(bytes(k)))
        return text


HTTP_CMCC = {

}
rd = StrictRedis()


def http_cmcc_send_code(mobile):
    http_login_cmcc_obj = HttpLoginCMCC(mobile)
    http_login_cmcc_obj.need_verify_code(mobile)
    http_login_cmcc_obj.send_first_code(mobile)
    return http_login_cmcc_obj


def http_cmcc_go_login(obj, sms_code):
    flag = obj.go_login(sms_code=sms_code)
    if flag:
        rd.setex('cmcc_cookie_{}'.format(obj.mobile), 864000, obj.get_cookies())
        result_output.set_msg(u'设置cookie成功')
    return flag


if __name__ == '__main__':

    try:
        mobile = ''
        if len(sys.argv) >= 2:
            mobile = sys.argv[1]
        else:
            result_output.set_code(20003)
            result_output.set_msg(u'参数错误')
            result_output.done()

        root_path = os.path.join(os.path.dirname(__file__), 'cmcc_pk')
        if not os.path.exists(root_path):
            os.mkdir(root_path)
        pk_path = os.path.join(root_path, '{}.pk'.format(mobile))
        if len(sys.argv) == 3:
            sms_code = sys.argv[2]
            if os.path.exists(pk_path):
                with open(pk_path, 'rb') as f:
                    obj = pickle.loads(f.read())
                    if not http_cmcc_go_login(obj, sms_code):
                        result_output.set_code(20002)
                os.remove(pk_path)
            else:
                result_output.set_code(20003)
        else:
            if os.path.exists(pk_path):
                os.remove(pk_path)
            obj = http_cmcc_send_code(mobile)
            with open(pk_path, 'wb') as f:
                f.write(pickle.dumps(obj))
    except Exception:
        import traceback

        result_output.set_code(20001)
        result_output.set_msg(traceback.format_exc())
    result_output.done()
