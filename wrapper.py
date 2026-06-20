
from flask import url_for, session, redirect, render_template


from functools import wraps
from flask import session, abort
import db


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'uid' not in session:
            return redirect('/user/login')
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 未登录直接跳转登录页
        if 'uid' not in session:
            return redirect(url_for("user.login"))
        # 查询当前用户是否为管理员
        user_info = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
        # user_info为空 或者 is_admin不等于1 则无权限
        if not user_info or user_info[0][0] != 1:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function