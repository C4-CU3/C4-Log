import os
import sys
# 用户站点：   用户模块 =》用户登录，用户注册，修改密码
#            博客模块 =》新建博客，博客一览，博客详细，博客搜索，博客删除，博客评论
# 管理员站点： 用户管理 =》用户查询，用户修改，用户删除
#            博客管理 =》博客搜索，博客删除，博客评论，博客修改
import os.path
from datetime import datetime

# 关键：把项目根目录加入模块搜索路径
CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(CUR_PATH)

from flask import Flask, render_template, request, redirect, url_for, session, Blueprint, abort
import sqlite3

base_dir = ''
if hasattr(sys, 'MEIPASS'):
    base_dir = os.path.join(sys._MEIPASS)

app = Flask(__name__, template_folder=os.path.join(base_dir, "templates"),
            static_folder=os.path.join(base_dir, "static"))

app.config['SECRET_KEY'] = "1qaz2wsd3edc4rfv5tear6yhn7um8ikk,9ol.0obvious987ytrdszpokbewafghkcvhgfergiugrtyf"

from controller_user import controller_user
app.register_blueprint(controller_user)
from controller_blog import controller_blog
app.register_blueprint(controller_blog)


# 解决打包后静态文件/模板路径问题
def resource_path(relative_path):
    """获取打包后文件的绝对路径"""
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller打包后的临时目录
        base_path = sys._MEIPASS
    else:
        # 开发环境路径
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


@app.context_processor
def inject_now():
    return {'now': datetime.now()}


@app.context_processor
def inject_user_info():
    is_login = 'uid' in session
    is_admin = False
    if is_login:
        # 假设user表有is_admin字段，查询当前用户是否为管理员
        import db
        user = db.query_sql("select is_admin from user where id = ?", [session['uid']])
        is_admin = user[0][0] if user else False
    return {'now': datetime.now(), 'is_login': is_login, 'is_admin': is_admin}


@app.context_processor
def inject_user_info():
    is_login = "uid" in session
    is_admin = False
    if is_login:
        import db
        res = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
        if res and res[0][0] == 1:
            is_admin = True
    return {"now": datetime.now(), "is_login": is_login, "is_admin": is_admin}


@app.route("/")
def index():
    return render_template("index.html")


# 执行以下代码生成哈希并更新到user表
from werkzeug.security import generate_password_hash
new_pwd_hash = generate_password_hash("你的密码", method='pbkdf2:sha256')
# UPDATE user SET password = ? WHERE name = ?，参数为[new_pwd_hash, "用户名"]


from flask import g, session
import db


# 全局上下文处理器：所有模板自动获得 user_info，每个页面不用手动传
@app.context_processor
def inject_user():
    user_info = None
    if "uid" in session:
        res = db.query_sql("SELECT avatar, name FROM user WHERE id = ?", [session["uid"]])
        if res:
            avatar = res[0][0]
            name = res[0][1]
            user_info = {
                "avatar": avatar,
                "name": name
            }
    return dict(user_info=user_info)


if __name__ == "__main__":
    app.run(debug=True, port=7020)
