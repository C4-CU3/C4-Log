from werkzeug.security import generate_password_hash, check_password_hash
import db

# 新增对外可用加密函数
def hash_pwd(raw_password):
    return generate_password_hash(raw_password, method="pbkdf2:sha256")

# 下面保留原来的批量转换脚本代码不变
all_user = db.query_sql("SELECT id, name, password FROM user")
if not all_user:
    print("用户表为空，无需转换")
else:
    count = 0
    for uid, name, plain_pwd in all_user:
        if len(plain_pwd) > 40:
            print(f"用户 {name} 密码已是哈希，跳过")
            continue
        hash_pwd_str = hash_pwd(plain_pwd)
        db.exec_sql("UPDATE user SET password = ? WHERE id = ?", [hash_pwd_str, uid])
        count += 1
        print(f"成功转换用户 {name}，原明文：{plain_pwd}")
    print(f"\n转换完成，共处理 {count} 个明文密码用户")