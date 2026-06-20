import sqlite3


def init_db():
    conn = sqlite3.connect("blog.db")
    cur = conn.cursor()
    # 创建评论表
    cur.execute('''
    CREATE TABLE IF NOT EXISTS comment (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blog_id INTEGER NOT NULL,
        uid INTEGER NOT NULL,
        content TEXT NOT NULL,
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (blog_id) REFERENCES blog(id),
        FOREIGN KEY (uid) REFERENCES user(id)
    )
    ''')
    # 创建好友表
    cur.execute('''
        CREATE TABLE IF NOT EXISTS friend (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status INTEGER NOT NULL DEFAULT 0,
            create_time INTEGER NOT NULL,
            UNIQUE(user_id, friend_id)
        )
    ''')
    # 自动添加缺失字段，重复运行不报错
    try:
        cur.execute("ALTER TABLE blog ADD COLUMN istop INTEGER DEFAULT 0;")
    except:
        pass
    try:
        cur.execute("ALTER TABLE blog ADD COLUMN isreview INTEGER DEFAULT 1;")
    except:
        pass
    try:
        cur.execute("ALTER TABLE blog ADD COLUMN create_time TEXT DEFAULT '';")
    except:
        pass
    # 新增分类字段
    try:
        cur.execute("ALTER TABLE blog ADD COLUMN category TEXT DEFAULT '默认随笔';")
    except:
        pass
    # 新增用户密码重置字段
    try:
        cur.execute("ALTER TABLE user ADD COLUMN reset_token TEXT DEFAULT NULL;")
    except:
        pass
    try:
        cur.execute("ALTER TABLE user ADD COLUMN reset_expire TEXT DEFAULT NULL;")
    except:
        pass
    conn.commit()
    cur.close()
    conn.close()


def query_sql(sql,param=[]):
    conn = sqlite3.connect("blog.db")
    cur = conn.cursor()
    cur.execute(sql, param)
    data = cur.fetchall()
    cur.close()
    conn.close()
    return data


def exec_sql(sql,param=[]):
    conn = sqlite3.connect("blog.db")
    cur = conn.cursor()
    cur.execute(sql, param)
    conn.commit()
    cur.close()
    conn.close()


# 程序启动自动执行建字段
init_db()