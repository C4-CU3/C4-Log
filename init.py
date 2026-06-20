import sqlite3

conn = sqlite3.connect("blog.db")

cur = conn.cursor()
# cur.execute("create table if not exists user(id integer primary key autoincrement, name, password)")
# cur.execute("create table if not exists blog(id integer primary key autoincrement, title, content,uid interger)")
# conn.commit()
cur.execute("select * from user")
v = cur.fetchall()
print(v)
conn.close()