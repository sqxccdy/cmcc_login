执行方式

发送
```
python http_login_start.py 1865773084
```

验证短信，并将cookie写入到redis
```
python http_login_start.py 1865773084 435323
```

| 类名 | code |备注 |
| -------- | -------- | ------- | 
| SendMsgMaxError | 90001| 发送短信到达最大值
| GlobalTimeoutError | 90002 | 全局业务超时
| UserTerminationError | 90003 | 因为用户操作导致业务无法进行
| SendMsgFaultError | 90004 | 触发运营商反扒机制
| UserOperaFaultError | 90005 | 用户操作失误
| ReLoginWorkFlow | 90006 | 登录重试异常
