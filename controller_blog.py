import os.path
import sqlite3
import db
from wrapper import login_required, admin_required
from flask import Flask, render_template, request, redirect, url_for, session, Blueprint, abort, flash

controller_blog = Blueprint("c4-log", __name__, url_prefix="/c4-log")


import secrets
from datetime import datetime, timedelta
# 密码哈希函数在 convert_pwd.py
from convert_pwd import hash_pwd
# 发邮件函数在 email_util.py
from email_util import send_email

# ---------------------- 忘记密码路由开始 ----------------------
# 1. 找回密码输入邮箱页面
@controller_blog.route('/forget_pwd')
def forget_pwd():
    return render_template("forget_pwd.html")


# 2. 发送重置邮件接口
@controller_blog.route('/send_reset_email', methods=["POST"])
def send_reset_email():
    email = request.form.get("email", "").strip()
    # 查询该邮箱用户
    user_row = db.query_sql("SELECT id,name FROM user WHERE email = ?", [email])
    if not user_row:
        flash("该邮箱未注册账号", "danger")
        return redirect(url_for("c4-log.forget_pwd"))
    uid, username = user_row[0]
    # 生成唯一重置令牌，有效期30分钟
    token = secrets.token_hex(32)
    expire_time = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
    # 存入数据库
    db.exec_sql("UPDATE user SET reset_token=?, reset_expire=? WHERE id=?", [token, expire_time, uid])
    # 重置链接 蓝图是 c4-log 不是 c4
    reset_url = url_for("c4-log.reset_password", token=token, _external=True)
    # 邮件内容
    mail_content = f"""
您好 {username}：
您申请重置C4-log登录密码，链接30分钟内有效：
{reset_url}
如非本人操作，请忽略此邮件。
"""
    send_email(email, "C4-log 密码重置", mail_content)
    flash("重置邮件已发送，请前往邮箱查收", "success")
    return redirect(url_for("c4-log.forget_pwd"))


# 3. 打开重置密码页面（带token校验）
@controller_blog.route('/reset_password/<token>')
def reset_password(token):
    now = datetime.now()
    # 查询有效token用户
    user_data = db.query_sql("SELECT id,reset_expire FROM user WHERE reset_token = ?", [token])
    if not user_data:
        flash("重置链接无效，请重新申请", "danger")
        return redirect(url_for("c4-log.forget_pwd"))
    uid, expire_str = user_data[0]
    expire_dt = datetime.strptime(expire_str, "%Y-%m-%d %H:%M:%S")
    if now > expire_dt:
        # 过期清空token
        db.exec_sql("UPDATE user SET reset_token=null, reset_expire=null WHERE id=?", [uid])
        flash("重置链接已过期，请重新申请", "danger")
        return redirect(url_for("c4-log.forget_pwd"))
    return render_template("reset_pwd.html", token=token)


# 4. 提交新密码
@controller_blog.route('/do_reset_pwd', methods=["POST"])
def do_reset_pwd():
    token = request.form.get("token")
    new_pwd = request.form.get("pwd", "").strip()
    confirm_pwd = request.form.get("confirm_pwd", "").strip()
    if new_pwd != confirm_pwd:
        flash("两次输入密码不一致", "danger")
        return redirect(url_for("c4-log.reset_password", token=token))
    if len(new_pwd) < 6:
        flash("密码至少6位字符", "danger")
        return redirect(url_for("c4-log.reset_password", token=token))
    # 校验token有效
    user_data = db.query_sql("SELECT id,reset_expire FROM user WHERE reset_token = ?", [token])
    if not user_data:
        flash("链接失效", "danger")
        return redirect(url_for("c4-log.forget_pwd"))
    uid, expire_str = user_data[0]
    if datetime.now() > datetime.strptime(expire_str, "%Y-%m-%d %H:%M:%S"):
        db.exec_sql("UPDATE user SET reset_token=null, reset_expire=null WHERE id=?", [uid])
        flash("链接过期", "danger")
        return redirect(url_for("c4-log.forget_pwd"))
    # 更新密码，清空重置令牌
    new_hash = hash_pwd(new_pwd)
    db.exec_sql("UPDATE user SET password=?, reset_token=null, reset_expire=null WHERE id=?", [new_hash, uid])
    flash("密码重置成功，请使用新密码登录", "success")
    return redirect(url_for("user.login"))
# ---------------------- 忘记密码路由结束 ----------------------


# 封装获取评论（带用户头像）函数，放在文件开头
def get_comments(blog_id):
    sql = """
        SELECT c.id, c.content, c.create_time, u.name, c.uid, u.avatar 
        FROM comment c 
        LEFT JOIN user u ON c.uid = u.id 
        WHERE c.blog_id = ?
        ORDER BY c.id ASC
    """
    comments = db.query_sql(sql, [blog_id])
    return comments


# 整数参数校验函数
def validate_int_param(param, default=0, min_val=1):
    """统一整数参数校验"""
    try:
        val = int(param)
        if val < min_val:
            return default
        return val
    except (TypeError, ValueError):
        return default


# show路由
@controller_blog.route('/show')
def show():
    return "show c4-log"


@controller_blog.route('/about')
def about():
    is_login = 'uid' in session
    is_admin = False
    if is_login:
        user_info = db.query_sql("SELECT is_admin FROM user WHERE id=?", [session["uid"]])
        if user_info and user_info[0][0] == 1:
            is_admin = True
    return render_template("about.html", is_login=is_login, is_admin=is_admin)


@controller_blog.route('/help')
def help():
    # 复用首页is_admin逻辑，传递给页面
    is_login = 'uid' in session
    is_admin = False
    if is_login:
        user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
        if user_row and user_row[0][0] == 1:
            is_admin = True
    return render_template("help.html", is_admin=is_admin, is_login=is_login)


# 添加博客仍需登录
@controller_blog.route('/add')
@login_required
def add():
    is_login = 'uid' in session
    is_admin = False
    if is_login:
        user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
        if user_row and user_row[0][0] == 1:
            is_admin = True
    return render_template('add.html', is_admin=is_admin)


# 提交添加仍需登录
@controller_blog.route('/do_add', methods=["POST"])
@login_required
def do_add():
    title = request.form.get("title")
    content = request.form.get("content")
    category = request.form.get("category", "默认随笔")
    create_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sql = """
        INSERT INTO blog(title,content,uid,istop,isreview,create_time,category) 
        VALUES (?,?,?,?,?,?,?)
    """
    params = [title, content, session["uid"], 0, 0, create_time, category]
    db.exec_sql(sql, params)
    return redirect(url_for("c4-log.index"))


# 删除博客仍需登录
@controller_blog.route('/delete')
@login_required
def delete():
    args = request.args
    id = args.get('id', '')
    if not id.isdigit():
        return "参数错误", 400
    id = int(id)
    # 查询这条博客完整数据（要取is_review）
    blog_info = db.query_sql("SELECT * FROM blog WHERE id = ?", [id])
    if not blog_info:
        return "log不存在",404
    blog = blog_info[0]

    # ========== 插入审核权限判断 ==========
    blog_owner_uid = blog[3]
    is_review = blog[5]
    user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
    is_admin = user_row[0][0] == 1 if user_row else False

    if blog_owner_uid != session['uid'] and not is_admin:
        return "无权限删除他人log",403
    if blog_owner_uid == session['uid'] and is_review == 1 and not is_admin:
        return "该log已审核，禁止自行删除，请联系管理员",403
    # ============= 判断结束 =============

    db.exec_sql("delete from blog where id = ?", [id])
    return redirect(url_for("c4-log.index"))


# 编辑博客仍需登录
@controller_blog.route("/edit")
@login_required
def edit():
    args = request.args
    id = args.get('id', '')
    data = db.query_sql("select * from blog where id = ?", [id])
    if not data:
        return "博客不存在", 404
    blog = data[0]

    # ========== 从这里开始插入审核权限判断 ==========
    blog_owner_uid = blog[3]
    is_review = blog[5]
    # 查询当前用户是否管理员
    user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
    is_admin = user_row[0][0] == 1 if user_row else False

    # 不是作者也不是管理员 → 无权限
    if blog_owner_uid != session['uid'] and not is_admin:
        return "无权编辑他人log",403
    # 是自己但已审核、且不是管理员 → 禁止修改
    if blog_owner_uid == session['uid'] and is_review == 1 and not is_admin:
        return "该log已审核，无法自行修改，请联系管理员",403
    # ============= 判断结束 =============

    return render_template("edit.html", blog=blog)


# 提交编辑仍需登录
@controller_blog.route("/do_edit", methods=["POST"])
@login_required
def do_edit():
    form = request.form
    id = form.get("id", "")
    title = form.get("title", "")
    content = form.get("content", "")

    # 先查博客信息
    blog_info = db.query_sql("SELECT * FROM blog WHERE id = ?", [id])
    if not blog_info:
        return "log不存在",404
    blog = blog_info[0]

    # ========== 插入审核权限判断 ==========
    blog_owner_uid = blog[3]
    is_review = blog[5]
    user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
    is_admin = user_row[0][0] == 1 if user_row else False

    if blog_owner_uid != session['uid'] and not is_admin:
        return "无权修改他人log",403
    if blog_owner_uid == session['uid'] and is_review == 1 and not is_admin:
        return "该日志已审核，无法自行修改，请联系管理员",403
    # ============= 判断结束 =============

    db.exec_sql("update blog set title = ?, content = ? where id = ?", [title, content, id])
    return redirect(url_for('c4-log.index'))


# 移除@login_required，游客可查看博客详情
@controller_blog.route('/detail/<int:blog_id>')
def detail(blog_id):
    # 统一整数参数校验，防止非法参数
    blog_id = validate_int_param(blog_id, default=0, min_val=1)
    if blog_id == 0:
        return "参数错误：博客ID必须为正整数", 400

    # 获取博客内容（仅一次查询，移除重复查询）
    blog_data = db.query_sql("SELECT * FROM blog WHERE id = ?", [blog_id])
    if not blog_data:
        return "log不存在", 404
    blog = blog_data[0]

    # 调用封装好的函数获取带用户头像的评论，删除冗余的评论查询逻辑
    comments = get_comments(blog_id)

    # 新增：判断用户是否登录（用于模板中控制评论按钮显示）
    is_login = 'uid' in session
    return render_template("detail.html", blog=blog, comments=comments, is_login=is_login)


# 提交评论仍需登录
@controller_blog.route('/do_comment/<int:blog_id>', methods=["POST"])
@login_required
def do_comment(blog_id):
    content = request.form.get("content", "").strip()
    if not content:
        return redirect(url_for("c4-log.detail", blog_id=blog_id))
    db.exec_sql("""
        INSERT INTO comment (blog_id, uid, content) 
        VALUES (?, ?, ?)
    """, [blog_id, session['uid'], content])
    return redirect(url_for("c4-log.detail", blog_id=blog_id))


# 删除评论仍需登录
@controller_blog.route('/delete_comment/<int:comment_id>')
@login_required
def delete_comment(comment_id):
    comment = db.query_sql("SELECT blog_id, uid FROM comment WHERE id = ?", [comment_id])
    if not comment:
        return "评论不存在", 404
    blog_id, comment_uid = comment[0]
    # 获取当前用户是否为管理员
    user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
    admin_check = user_row[0][0] == 1 if user_row else False
    if comment_uid != session['uid'] and not admin_check:
        return "无权限删除", 403
    db.exec_sql("DELETE FROM comment WHERE id = ?", [comment_id])
    return redirect(url_for('c4-log.detail', blog_id=blog_id))


# 编辑评论仍需登录
@controller_blog.route('/edit_comment/<int:comment_id>', methods=["GET", "POST"])
@login_required
def edit_comment(comment_id):
    comment = db.query_sql("SELECT * FROM comment WHERE id = ?", [comment_id])
    if not comment:
        return "评论不存在", 404
    comment = comment[0]
    comment_id, blog_id, comment_uid, content, create_time = comment
    # 获取当前用户是否为管理员
    user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
    admin_check = user_row[0][0] == 1 if user_row else False
    if comment_uid != session['uid'] and not admin_check:
        return "无权限编辑", 403
    if request.method == "GET":
        return render_template("edit_comment.html", comment=comment)
    else:
        new_content = request.form.get("content", "").strip()
        if not new_content:
            return render_template("edit_comment.html", comment=comment, error="评论内容不能为空")
        db.exec_sql("UPDATE comment SET content = ? WHERE id = ?", [new_content, comment_id])
        return redirect(url_for('c4-log.detail', blog_id=blog_id))


# 置顶博客（管理员）
@controller_blog.route('/top/<int:blog_id>')
@admin_required
def top_blog(blog_id):
    db.exec_sql("UPDATE blog SET istop=1 WHERE id=?", [blog_id])
    return redirect(url_for('c4-log.index'))


# 取消置顶（管理员）
@controller_blog.route('/untop/<int:blog_id>')
@admin_required
def untop_blog(blog_id):
    db.exec_sql("UPDATE blog SET istop=0 WHERE id=?", [blog_id])
    return redirect(url_for('c4-log.index'))


# 管理员审核通过
@controller_blog.route('/review/<int:blog_id>')
@admin_required
def review_blog(blog_id):
    db.exec_sql("UPDATE blog SET isreview=1 WHERE id=?", [blog_id])
    return redirect(url_for('c4-log.index'))


# 撤销审核（管理员）
@controller_blog.route('/unreview_blog', methods=["GET"])
@controller_blog.route('/unreview/<int:blog_id>')
@admin_required
def unreview_blog(blog_id):
    db.exec_sql("UPDATE blog SET isreview=0 WHERE id=?", [blog_id])
    return redirect(url_for('c4-log.index'))


# 批量操作接口
@controller_blog.route("/batch", methods=["POST"])
@admin_required
def batch_operate():
    ids_str = request.form.get("ids", "")
    op_type = request.form.get("op_type", "")  # 现在能正确获取前端传递的op_type
    # 补充：获取搜索关键词和页码（从表单或GET参数）
    key = request.form.get("key", request.args.get("key", ""))
    page = request.form.get("page", request.args.get("page", 1))

    if not ids_str or not op_type:
        return redirect(url_for("c4-log.index", key=key, page=page))

    # 分割id列表并校验
    try:
        id_arr = [int(i) for i in ids_str.split(",")]
    except ValueError:
        return redirect(url_for("c4-log.index", key=key, page=page))

    # 执行批量操作
    if op_type == "review":
        # 批量通过审核
        for bid in id_arr:
            db.exec_sql("UPDATE blog SET isreview=1 WHERE id=?", [bid])
    elif op_type == "unreview":
        # 批量撤销审核
        for bid in id_arr:
            db.exec_sql("UPDATE blog SET isreview=0 WHERE id=?", [bid])
    elif op_type == "delete":
        # 批量删除
        for bid in id_arr:
            # 复用删除权限逻辑（可选，增强安全性）
            blog_info = db.query_sql("SELECT * FROM blog WHERE id = ?", [bid])
            if blog_info:
                db.exec_sql("DELETE FROM blog WHERE id = ?", [bid])

    # 跳转回原页面，保留搜索和页码
    return redirect(url_for("c4-log.index", key=key, page=page))


# Python游戏分类独立页面
@controller_blog.route('/python/game')
def python_game():
    key = "游戏"
    page = int(request.args.get("page", "1"))
    if page < 1:
        page = 1
    number_per_page = 10
    offset = (page - 1) * number_per_page
    limit = number_per_page
    key1 = f"%{key}%"
    key2 = f"%{key}%"

    # 登录管理员判断
    is_login = 'uid' in session
    is_admin = False
    if is_login:
        user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
        if user_row and user_row[0][0] == 1:
            is_admin = True

    if is_admin:
        sql_count = "SELECT count(*) FROM blog WHERE title LIKE ? OR content LIKE ?"
        sql_list = """
        SELECT id,title,content,uid,istop,isreview,create_time
        FROM blog 
        WHERE (title LIKE ? OR content LIKE ?)
        ORDER BY istop DESC, isreview ASC, id DESC 
        LIMIT ?,?
        """
        params = [key1, key2, offset, limit]
        count_params = [key1, key2]
    else:
        sql_count = "SELECT count(*) FROM blog WHERE (title LIKE ? OR content LIKE ?) AND isreview = 1"
        sql_list = """
        SELECT id,title,content,uid,istop,isreview,create_time
        FROM blog 
        WHERE (title LIKE ? OR content LIKE ?) AND isreview = 1 
        ORDER BY istop DESC, id DESC 
        LIMIT ?,?
        """
        params = [key1, key2, offset, limit]
        count_params = [key1, key2]

    total_count = db.query_sql(sql_count, count_params)
    total_count = total_count[0][0] if total_count else 0
    total_page = (total_count + number_per_page - 1) // number_per_page
    # 页码修正，防止超页
    if page > total_page and total_page > 0:
        page = total_page
    blogs = db.query_sql(sql_list, params)

    return render_template("python/game.html",
                           blogs=blogs, page=page, total_page=total_page,
                           total_count=total_count, is_admin=is_admin, is_login=is_login,
                           cate_name="Python游戏开发", cate_key=key)


# Python工具分类独立页面
@controller_blog.route('/python/tool')
def python_tool():
    key = "工具"
    page = int(request.args.get("page", "1"))
    if page < 1:
        page = 1
    number_per_page = 10
    offset = (page - 1) * number_per_page
    limit = number_per_page
    key1 = f"%{key}%"
    key2 = f"%{key}%"

    is_login = 'uid' in session
    is_admin = False
    if is_login:
        user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
        if user_row and user_row[0][0] == 1:
            is_admin = True

    if is_admin:
        sql_count = "SELECT count(*) FROM blog WHERE title LIKE ? OR content LIKE ?"
        sql_list = "SELECT id,title,content,uid,istop,isreview,create_time FROM blog WHERE (title LIKE ? OR content LIKE ?) ORDER BY istop DESC, isreview ASC, id DESC LIMIT ?,?"
        params = [key1, key2, offset, limit]
        count_params = [key1, key2]
    else:
        sql_count = "SELECT count(*) FROM blog WHERE (title LIKE ? OR content LIKE ?) AND isreview = 1"
        sql_list = "SELECT id,title,content,uid,istop,isreview,create_time FROM blog WHERE (title LIKE ? OR content LIKE ?) AND isreview = 1 ORDER BY istop DESC, id DESC LIMIT ?,?"
        params = [key1, key2, offset, limit]
        count_params = [key1, key2]

    total_count = db.query_sql(sql_count, count_params)[0][0] if db.query_sql(sql_count, count_params) else 0
    total_page = (total_count + number_per_page - 1) // number_per_page
    if page > total_page and total_page > 0:
        page = total_page
    blogs = db.query_sql(sql_list, params)

    return render_template("python/tool.html",
                           blogs=blogs, page=page, total_page=total_page,
                           total_count=total_count, is_admin=is_admin, is_login=is_login,
                           cate_name="Python工具脚本", cate_key=key)


# Python其他项目
@controller_blog.route('/python/other')
def python_other():
    key = "Python项目"
    page = int(request.args.get("page", "1"))
    if page < 1:
        page = 1
    number_per_page = 10
    offset = (page - 1) * number_per_page
    limit = number_per_page
    key1 = f"%{key}%"
    key2 = f"%{key}%"

    is_login = 'uid' in session
    is_admin = False
    if is_login:
        user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
        if user_row and user_row[0][0] == 1:
            is_admin = True

    if is_admin:
        sql_count = "SELECT count(*) FROM blog WHERE title LIKE ? OR content LIKE ?"
        sql_list = "SELECT id,title,content,uid,istop,isreview,create_time FROM blog WHERE (title LIKE ? OR content LIKE ?) ORDER BY istop DESC, isreview ASC, id DESC LIMIT ?,?"
        params = [key1, key2, offset, limit]
        count_params = [key1, key2]
    else:
        sql_count = "SELECT count(*) FROM blog WHERE (title LIKE ? OR content LIKE ?) AND isreview = 1"
        sql_list = "SELECT id,title,content,uid,istop,isreview,create_time FROM blog WHERE (title LIKE ? OR content LIKE ?) AND isreview = 1 ORDER BY istop DESC, id DESC LIMIT ?,?"
        params = [key1, key2, offset, limit]
        count_params = [key1, key2]

    total_count = db.query_sql(sql_count, count_params)[0][0] if db.query_sql(sql_count, count_params) else 0
    total_page = (total_count + number_per_page - 1) // number_per_page
    if page > total_page and total_page > 0:
        page = total_page
    blogs = db.query_sql(sql_list, params)

    return render_template("python/other.html",
                           blogs=blogs, page=page, total_page=total_page,
                           total_count=total_count, is_admin=is_admin, is_login=is_login,
                           cate_name="Python综合项目", cate_key=key)


# 论坛页面
@controller_blog.route('/forum')
def forum():
    return render_template("forum.html")


# 2026科隆Major论坛板块
@controller_blog.route('/forum/cologne_major_2026')
def forum_cologne_major_2026():
    is_login = 'uid' in session
    is_admin = False
    if is_login:
        user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
        if user_row and user_row[0][0] == 1:
            is_admin = True
    # 模拟2026科隆Major信息（实际可从数据库/接口获取）
    major_info = {
        "title": "2026科隆Major 核心信息",
        "time": "预计2026年8月（参考往届时间）",
        "location": "德国科隆LANXESS arena",
        "game": "CS2（反恐精英2）",
        "key_points": [
            "参赛队伍：预计24支（包含各赛区晋级队伍）",
            "赛制：小组赛+淘汰赛（BO3/BO5）",
            "奖金池：参考往届约125万美元（具体以官方为准）",
            "中国队参赛：需通过亚洲赛区RMR晋级",
            "直播平台：Twitch、虎牙、B站等（待定）"
        ]
    }
    return render_template("forum/cologne_major_2026.html",
                           is_login=is_login, is_admin=is_admin,
                           major_info=major_info)

# 2026广东中考论坛板块
@controller_blog.route('/forum/guangdong_zhongkao_2026')
def forum_guangdong_zhongkao_2026():
    is_login = 'uid' in session
    is_admin = False
    if is_login:
        user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
        if user_row and user_row[0][0] == 1:
            is_admin = True
    # 2026广东中考核心信息（基于政策延续性+官方草案）
    zhongkao_info = {
        "title": "2026年广东省中考 核心政策与信息",
        "exam_time": "预计2026年6月20-22日（参考往届）",
        "subjects": [
            "必考：语文（120分）、数学（120分）、英语（120分，含听说）",
            "物理/历史二选一（各100分）",
            "化学/政治/生物/地理四选二（各100分）",
            "体育与健康（70分，计入总分）"
        ],
        "total_score": "满分830分（参考2025年政策，2026年或微调）",
        "key_policy": [
            "指标到校：优质高中名额分配至初中比例不低于50%",
            "命题：省教育考试院统一命题，严禁超纲",
            "录取：分批次录取（提前批、第一批、第二批）",
            "加分政策：烈士子女、现役军人子女等可加分（最高20分）",
            "新变化：部分地市试点“职教高考”衔接，中职升学通道拓宽"
        ],
        "备考建议": [
            "关注广东省教育考试院官网发布的最新考纲",
            "重视体育日常训练（长跑、球类等必考项）",
            "英语听说考试提前准备（机考形式）",
            "物理/历史选科结合自身优势与升学规划"
        ]
    }
    return render_template("forum/guangdong_zhongkao_2026.html",
                           is_login=is_login, is_admin=is_admin,
                           zhongkao_info=zhongkao_info)


@controller_blog.route('/')
def index():
    args = request.args
    key = args.get("key", "")
    page = int(args.get("page", "1"))
    if page < 1:
        page = 1

    # 先定义每页条数
    number_per_page = 10
    offset = (page - 1) * number_per_page
    limit = number_per_page
    key1 = f"%{key}%"
    key2 = f"%{key}%"

    is_login = 'uid' in session
    is_admin = False
    if is_login:
        user_row = db.query_sql("SELECT is_admin FROM user WHERE id = ?", [session["uid"]])
        if user_row and user_row[0][0] == 1:
            is_admin = True

    if is_admin:
        sql_count = "SELECT count(*) FROM blog WHERE title LIKE ? OR content LIKE ?"
        sql_list = """
        SELECT id,title,content,uid,istop,isreview,create_time
        FROM blog 
        WHERE (title LIKE ? OR content LIKE ?)
        ORDER BY istop DESC, isreview ASC, id DESC 
        LIMIT ?,?
        """
        count_params = [key1, key2]
        list_params = [key1, key2, offset, limit]
    else:
        sql_count = "SELECT count(*) FROM blog WHERE (title LIKE ? OR content LIKE ?) AND isreview = 1"
        sql_list = """
        SELECT id,title,content,uid,istop,isreview,create_time
        FROM blog 
        WHERE (title LIKE ? OR content LIKE ?) AND isreview = 1 
        ORDER BY istop DESC, id DESC 
        LIMIT ?,?
        """
        count_params = [key1, key2]
        list_params = [key1, key2, offset, limit]

    total_count = db.query_sql(sql_count, count_params)
    total_count = total_count[0][0] if total_count else 0

    # 先拿到total_count、number_per_page，再计算总页数
    total_page = (total_count + number_per_page - 1) // number_per_page
    # 页码超限修正
    if page > total_page and total_page > 0:
        page = total_page

    blogs = db.query_sql(sql_list, list_params)

    return render_template(
        "index.html",
        blogs=blogs,
        page=page,
        total_page=total_page,
        total_count=total_count,
        is_login=is_login,
        is_admin=is_admin
    )