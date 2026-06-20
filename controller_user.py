import os.path
import os
import uuid
from flask import request
from werkzeug.utils import secure_filename
import time
from flask import jsonify
from email_util import send_email_code as send_email_code_util
import sqlite3
import db
from wrapper import login_required, admin_required
from flask import Flask, render_template, request, redirect, url_for, session, Blueprint, abort
# 导入哈希相关函数
from werkzeug.security import generate_password_hash, check_password_hash
import db

controller_user = Blueprint("user", __name__, url_prefix="/user")


@controller_user.route('/show')
def show():
    return "show user"


@controller_user.route('/login')
def login():
    return render_template("Login.html")


@controller_user.route('/logout')
@login_required
def logout():
    del session['uid']
    return redirect(url_for('user.login'))


@controller_user.route('/do_login', methods=["POST"])
def do_login():
    form = request.form
    name = form.get("name", "")
    password = form.get("password", '')

    # 先查询用户信息
    result = db.query_sql("select * from user where name = ?", (name,))

    # 找到用户且密码匹配
    if len(result) > 0 and check_password_hash(result[0][2], password):  # 假设password是第三列
        session['uid'] = result[0][0]
        return redirect(url_for("c4-log.index"))
    # 没有找到用户或密码错误
    else:
        return render_template("Login.html", error="用户名或密码错误")


@controller_user.route('/register')
def register():
    return render_template("register.html")


@controller_user.route("/do_register", methods=["POST"])
def do_register():
    form = request.form
    name = form.get("name", "").strip()
    email = form.get("email", "").strip()
    input_code = form.get("email_code", "").strip()
    password = form.get("password", '')
    password2 = form.get("password2", '')

    # 基础校验
    if password != password2:
        return render_template("register.html", error="两次输入密码不一致")
    if not name:
        return render_template("register.html", error="用户名不能为空")
    if not password:
        return render_template("register.html", error="密码不能为空")
    if "@" not in email:
        return render_template("register.html", error="邮箱格式不正确")
    if len(input_code) != 6:
        return render_template("register.html", error="请输入正确的6位数字验证码")

    # 查询该邮箱保存的验证码
    code_data = db.query_sql("SELECT code, expire FROM email_codes WHERE email = ?", [email])
    if not code_data:
        return render_template("register.html", error="请先获取邮箱验证码")
    db_code, expire_ts = code_data[0]

    # 验证码校验
    if db_code != input_code:
        return render_template("register.html", error="验证码错误")
    now_ts = int(time.time())
    if now_ts > expire_ts:
        return render_template("register.html", error="验证码已过期，请重新获取")

    # 判断邮箱是否已被注册
    exist_email = db.query_sql("SELECT id FROM user WHERE email = ?", [email])
    if exist_email:
        return render_template("register.html", error="该邮箱已绑定账号，请勿重复注册")

    # 插入新用户，清空验证码
    from werkzeug.security import generate_password_hash
    pwd_hash = generate_password_hash(password, method="pbkdf2:sha256")
    db.exec_sql(
        "INSERT INTO user(name, password, email, email_code, email_expire) VALUES (?,?,?,null,0)",
        [name, pwd_hash, email]
    )
    return redirect(url_for("user.login"))


@controller_user.route('/change_password')
@login_required
def change_password():
    return render_template("change_password.html")


@controller_user.route("/user_list")
@admin_required
def user_list():
    users = db.query_sql("select * from user")

    return render_template("user_list.html", users=users)


@controller_user.route("/user_delete")
@admin_required
def user_delete():
    args = request.args
    id = int(args.get("id", "0"))

    db.exec_sql("delete from user where id = ?", [id])

    return redirect(url_for("user.user_list"))


@controller_user.route('/send_email_code')
def send_email_code_route():  # 改路由函数名
    email = request.args.get("email", "").strip()
    if "@" not in email:
        return jsonify({"msg": "邮箱格式错误"})

    code, expire = send_email_code_util(email)  # 调用正确的函数
    if not code:
        return jsonify({"msg": "邮件发送失败，请检查邮箱配置"})

    exist = db.query_sql("SELECT 1 FROM email_codes WHERE email=?", [email])
    if exist:
        db.exec_sql("UPDATE email_codes SET code=?,expire=? WHERE email=?", [code, expire, email])
    else:
        db.exec_sql("INSERT INTO email_codes(email,code,expire) VALUES (?,?,?)", [email, code, expire])
    return jsonify({"msg": "验证码已发送，请查收"})


@controller_user.route("/update_pwd", methods=["POST"])
@login_required
def update_pwd():
    form = request.form
    old_pwd = form.get("old_pwd","")
    new_pwd = form.get("new_pwd","")
    new_pwd2 = form.get("new_pwd2","")
    uid = session["uid"]

    user = db.query_sql("SELECT password FROM user WHERE id=?", [uid])[0]
    pwd_hash = user[0]

    # 校验原密码
    if not check_password_hash(pwd_hash, old_pwd):
        return render_template("profile.html", user=user, error="原密码错误")
    if new_pwd != new_pwd2:
        return render_template("profile.html", user=user, error="两次新密码不一致")
    if len(new_pwd) < 4:
        return render_template("profile.html", user=user, error="密码长度至少4位")

    # 更新密码
    new_hash = generate_password_hash(new_pwd, method="pbkdf2:sha256")
    db.exec_sql("UPDATE user SET password=? WHERE id=?", [new_hash, uid])
    user_info = db.query_sql("SELECT id,name,password,email,is_admin FROM user WHERE id=?", [uid])[0]
    return render_template("profile.html", user=user_info, msg="密码修改成功！")


@controller_user.route("/update_email", methods=["POST"])
@login_required
def update_email():
    form = request.form
    new_email = form.get("new_email","").strip()
    input_code = form.get("email_code","").strip()
    uid = session["uid"]

    # 校验验证码
    code_row = db.query_sql("SELECT code,expire FROM email_codes WHERE email=?", [new_email])
    now = int(time.time())
    if not code_row:
        user = db.query_sql("SELECT id,name,password,email,is_admin FROM user WHERE id=?", [uid])[0]
        return render_template("profile.html", user=user, error="请先获取验证码")
    db_code, exp = code_row[0]
    if db_code != input_code:
        user = db.query_sql("SELECT id,name,password,email,is_admin FROM user WHERE id=?", [uid])[0]
        return render_template("profile.html", user=user, error="验证码错误")
    if now > exp:
        user = db.query_sql("SELECT id,name,password,email,is_admin FROM user WHERE id=?", [uid])[0]
        return render_template("profile.html", user=user, error="验证码已过期")

    # 判断邮箱是否被他人占用
    exist = db.query_sql("SELECT id FROM user WHERE email=? AND id != ?", [new_email, uid])
    if exist:
        user = db.query_sql("SELECT id,name,password,email,is_admin FROM user WHERE id=?", [uid])[0]
        return render_template("profile.html", user=user, error="该邮箱已被其他账号绑定")

    # 更新邮箱
    db.exec_sql("UPDATE user SET email=? WHERE id=?", [new_email, uid])
    user_info = db.query_sql("SELECT id,name,password,email,is_admin FROM user WHERE id=?", [uid])[0]
    return render_template("profile.html", user=user_info, msg="邮箱更换成功！")


from flask import Blueprint, render_template, session, redirect, url_for
import db


# 个人资料页面
@controller_user.route("/profile")
def profile():
    # 未登录拦截
    if "uid" not in session:
        flash("请先登录", "warning")
        return redirect(url_for("user.login"))

    uid = session["uid"]
    # 查询当前登录用户信息
    user_info = db.query_sql("SELECT id,name,password,email,is_admin,avatar FROM user WHERE id=?", [uid])[0]

    # 核心：查询该用户发布的所有博客
    my_blogs = db.query_sql("""
        SELECT id, title, content, create_time 
        FROM blog 
        WHERE uid = ?
        ORDER BY id DESC
    """, [uid])

    # 传给模板
    return render_template("profile.html", user=user_info, my_blogs=my_blogs)


# 头像上传配置
UPLOAD_FOLDER = "static/avatar"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS


@controller_user.route("/upload_avatar", methods=["POST"])
@login_required
def upload_avatar():
    uid = session["uid"]
    file = request.files.get("avatar")
    if not file or file.filename == "":
        user = db.query_sql("SELECT id,name,password,email,is_admin,avatar FROM user WHERE id=?", [uid])[0]
        return render_template("profile.html", user=user, error="请选择图片文件")
    if not allowed_file(file.filename):
        user = db.query_sql("SELECT id,name,password,email,is_admin,avatar FROM user WHERE id=?", [uid])[0]
        return render_template("profile.html", user=user, error="仅支持 png/jpg/jpeg 图片")

    # 生成唯一文件名，防止重名覆盖
    ext = file.filename.rsplit(".",1)[1].lower()
    new_name = f"{uuid.uuid4()}.{ext}"
    save_path = os.path.join(UPLOAD_FOLDER, new_name)
    file.save(save_path)
    # 存入数据库相对路径
    db_path = f"avatar/{new_name}"
    db.exec_sql("UPDATE user SET avatar=? WHERE id=?", [db_path, uid])

    user_info = db.query_sql("SELECT id,name,password,email,is_admin,avatar FROM user WHERE id=?", [uid])[0]
    return render_template("profile.html", user=user_info, msg="头像上传成功！")


@controller_user.route("/update_name", methods=["POST"])
@login_required
def update_name():
    uid = session["uid"]
    new_name = request.form.get("new_name", "").strip()

    # 简单校验
    if not new_name:
        user = db.query_sql("SELECT id,name,password,email,is_admin,avatar FROM user WHERE id=?", [uid])[0]
        return render_template("profile.html", user=user, error="用户名不能为空")
    if len(new_name) > 20:
        user = db.query_sql("SELECT id,name,password,email,is_admin,avatar FROM user WHERE id=?", [uid])[0]
        return render_template("profile.html", user=user, error="用户名不能超过20个字符")

    # 判断用户名是否已被他人占用
    exist = db.query_sql("SELECT id FROM user WHERE name = ? AND id != ?", [new_name, uid])
    if exist:
        user = db.query_sql("SELECT id,name,password,email,is_admin,avatar FROM user WHERE id=?", [uid])[0]
        return render_template("profile.html", user=user, error="该用户名已被占用，请更换")

    # 更新用户名
    db.exec_sql("UPDATE user SET name = ? WHERE id = ?", [new_name, uid])
    # 重新查询用户信息刷新页面
    user_info = db.query_sql("SELECT id,name,password,email,is_admin,avatar FROM user WHERE id=?", [uid])[0]
    return render_template("profile.html", user=user_info, msg="用户名修改成功！")


@controller_user.route("/friend")
@login_required
def friend():
    uid = session["uid"]
    now = int(time.time())
    # 已同意好友
    sql_friend = """
    SELECT u.id, u.name, u.avatar
    FROM friend f
    LEFT JOIN user u ON (f.user_id = u.id OR f.friend_id = u.id)
    WHERE f.status = 1 AND ((f.user_id = ? AND u.id != ?) OR (f.friend_id = ? AND u.id != ?))
    """
    friends = db.query_sql(sql_friend, [uid, uid, uid, uid])
    # 提取所有好友id
    friend_ids = [row[0] for row in friends]
    friend_ids.append(uid) # 排除自己
    # 收到的申请
    sql_apply = """
    SELECT u.id, u.name, u.avatar, f.id as apply_id
    FROM friend f
    LEFT JOIN user u ON f.user_id = u.id
    WHERE f.friend_id = ? AND f.status = 0
    """
    apply_list = db.query_sql(sql_apply, [uid])

    # 推荐用户：随机5个不是自己、不是好友的用户
    if friend_ids:
        placeholders = ",".join(["?"] * len(friend_ids))
        sql_rec = f"SELECT id,name,avatar FROM user WHERE id NOT IN ({placeholders}) ORDER BY RANDOM() LIMIT 5"
        recommend = db.query_sql(sql_rec, friend_ids)
    else:
        sql_rec = "SELECT id,name,avatar FROM user ORDER BY RANDOM() LIMIT 5"
        recommend = db.query_sql(sql_rec)

    # 搜索结果默认空
    search_res = []
    kw = ""
    return render_template("friend.html", friends=friends, apply_list=apply_list, recommend=recommend, search_res=search_res, kw=kw)


from flask import flash

@controller_user.route("/send_friend/<int:target_uid>", methods=["POST"])
@login_required
def send_friend(target_uid):
    uid = session["uid"]
    if uid == target_uid:
        flash("不能添加自己为好友", "danger")
        return redirect(url_for("user.friend"))
    # 判断是否已有申请/好友关系
    exist = db.query_sql("SELECT id FROM friend WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)",
                         [uid, target_uid, target_uid, uid])
    if exist:
        flash("已发送过申请或已是好友，无需重复操作", "warning")
        return redirect(url_for("user.friend"))
    t = int(time.time())
    db.exec_sql("INSERT INTO friend(user_id, friend_id, status, create_time) VALUES (?,?,0,?)",
                [uid, target_uid, t])
    # 成功提示
    flash("好友申请发送成功，等待对方同意！", "success")
    return redirect(url_for("user.friend"))


@controller_user.route("/deal_friend/<int:apply_id>/<int:opt>", methods=["POST"])
@login_required
def deal_friend(apply_id, opt):
    # opt=1同意，opt=2拒绝
    uid = session["uid"]
    # 只能处理发给自己的申请
    row = db.query_sql("SELECT id,friend_id FROM friend WHERE id=? AND friend_id=? AND status=0", [apply_id, uid])
    if not row:
        return "无权限操作",403
    if opt == 1:
        db.exec_sql("UPDATE friend SET status=1 WHERE id=?", [apply_id])
    else:
        db.exec_sql("UPDATE friend SET status=2 WHERE id=?", [apply_id])
    return redirect(url_for("user.friend"))


@controller_user.route("/del_friend/<int:fid>", methods=["POST"])
@login_required
def del_friend(fid):
    uid = session["uid"]
    db.exec_sql("DELETE FROM friend WHERE ((user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)) AND status=1",
                [uid, fid, fid, uid])
    flash("已删除该好友", "info")
    return redirect(url_for("user.friend"))


@controller_user.route("/search_user")
@login_required
def search_user():
    uid = session["uid"]
    keyword = request.args.get("kw", "").strip()
    # 先统一查询好友、申请、推荐（和/friend逻辑完全一致）
    sql_friend = """
    SELECT u.id, u.name, u.avatar
    FROM friend f
    LEFT JOIN user u ON (f.user_id = u.id OR f.friend_id = u.id)
    WHERE f.status = 1 AND ((f.user_id = ? AND u.id != ?) OR (f.friend_id = ? AND u.id != ?))
    """
    friends = db.query_sql(sql_friend, [uid, uid, uid, uid])

    sql_apply = """
    SELECT u.id, u.name, u.avatar, f.id as apply_id
    FROM friend f
    LEFT JOIN user u ON f.user_id = u.id
    WHERE f.friend_id = ? AND f.status = 0
    """
    apply_list = db.query_sql(sql_apply, [uid])

    # 推荐用户逻辑
    friend_ids = [row[0] for row in friends]
    friend_ids.append(uid)
    if friend_ids:
        placeholders = ",".join(["?"] * len(friend_ids))
        sql_rec = f"SELECT id,name,avatar FROM user WHERE id NOT IN ({placeholders}) ORDER BY RANDOM() LIMIT 5"
        recommend = db.query_sql(sql_rec, friend_ids)
    else:
        sql_rec = "SELECT id,name,avatar FROM user ORDER BY RANDOM() LIMIT 5"
        recommend = db.query_sql(sql_rec)

    # 搜索结果
    search_res = []
    if keyword:
        sql = "SELECT id,name,avatar FROM user WHERE name LIKE ? AND id != ?"
        search_res = db.query_sql(sql, [f"%{keyword}%", uid])

    kw = keyword
    # 所有模板变量全部传齐，缺一不可
    return render_template(
        "friend.html",
        friends=friends,
        apply_list=apply_list,
        recommend=recommend,
        search_res=search_res,
        kw=kw
    )


# 他人主页路由：访问别人资料
@controller_user.route("/profile/<int:visit_uid>")
@login_required
def other_profile(visit_uid):
    # 当前登录用户id
    login_uid = session["uid"]

    # 新增：自己访问自己主页直接跳转个人资料页
    if login_uid == visit_uid:
        return redirect(url_for("user.profile"))

    # 查询被访问用户的基础信息（头像、名字、管理员标识）
    user_data = db.query_sql("""
        SELECT id, name, email, is_admin, avatar
        FROM user WHERE id = ?
    """, [visit_uid])
    if not user_data:
        return "该用户不存在", 404
    target_user = user_data[0]

    # 查询该用户发布的所有博客
    user_blogs = db.query_sql("""
        SELECT id, title, content, create_time
        FROM blog WHERE uid = ? ORDER BY id DESC
    """, [visit_uid])

    # 判断当前登录用户是否和访问用户是好友（可选，用于权限控制）
    is_friend = False
    friend_check = db.query_sql("""
        SELECT id FROM friend
        WHERE status=1 AND ((user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?))
    """, [login_uid, visit_uid, visit_uid, login_uid])
    if friend_check:
        is_friend = True

    return render_template("other_profile.html",
                           user=target_user,
                           blogs=user_blogs,
                           is_friend=is_friend)