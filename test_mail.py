from email_util import send_email_code
code, t = send_email_code("bujishuijiao@163.com")
print("验证码", code)