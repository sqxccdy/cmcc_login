from abc import ABC

from redis import StrictRedis

import requests
import logging
import re
import time

logger = logging.getLogger('YYS')
rd = StrictRedis()


def now_ts_in_millis():
    return int(time.time() * 1000)


class MySession(requests.Session):
    def post(self, url, data=None, json=None, **kwargs):
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 5
        try:
            return super(MySession, self).post(url, data, json, **kwargs)
        except (requests.exceptions.ReadTimeout, requests.exceptions.Timeout):
            logger.debug('请求连接超时，重试一次. url: {}'.format(url))
            return super(MySession, self).post(url, data, json, **kwargs)


class HttpBasic(ABC):
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
        self._crawler_session.verifyCode = ''
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
            req.headers['Cookie'] = ';'.join(
                [f'{cookie.name}={cookie.value}' for cookie in self._crawler_session.cookies])
        # 'Cookie': ';'.join([f'{cookie.name}={cookie.value}'for cookie in self._crawler_session.cookies])
        #  处理headers
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
        logger.log(method, msg)
