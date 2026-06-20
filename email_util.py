import random
import time
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr

# QQ邮箱配置（替换成你自己的）
MAIL_SENDER = "c4-log@qq.com"
MAIL_ALIAS = "C4-log系统"
MAIL_PASSWORD = "ulsqwdyxjhdceaeg"
MAIL_HOST = "smtp.qq.com"
MAIL_PORT = 465


def send_email_code(target_email):
    code = "".join(random.choices("0123456789", k=6))
    expire_time = int(time.time()) + 300
    content = f"【C4-log】您的验证码：{code}，5分钟内有效，请勿泄露给他人。"

    msg = MIMEText(content, "plain", "utf-8")
    # 核心修复：标准格式化From，完全符合RFC协议
    msg['From'] = formataddr((MAIL_ALIAS, MAIL_SENDER))
    msg['To'] = target_email
    msg['Subject'] = Header("C4-log 平台验证码", "utf-8")

    try:
        server = smtplib.SMTP_SSL(MAIL_HOST, MAIL_PORT)
        server.login(MAIL_SENDER, MAIL_PASSWORD)
        server.sendmail(MAIL_SENDER, [target_email], msg.as_string())
        server.quit()
        print(f"邮件发送成功，目标:{target_email} 验证码:{code} 过期时间:{expire_time}")
        return code, expire_time
    except Exception as e:
        print(f"发送失败，邮箱:{target_email} 错误信息：{str(e)}")
        return None, 0


# 新增通用发邮件函数（给忘记密码重置邮件使用）
def send_email(to_email, subject, content):
    msg = MIMEText(content, "plain", "utf-8")
    msg['From'] = formataddr((MAIL_ALIAS, MAIL_SENDER))
    msg['To'] = to_email
    msg['Subject'] = Header(subject, "utf-8")
    server = smtplib.SMTP_SSL(MAIL_HOST, MAIL_PORT)
    server.login(MAIL_SENDER, MAIL_PASSWORD)
    server.sendmail(MAIL_SENDER, [to_email], msg.as_string())
    server.quit()