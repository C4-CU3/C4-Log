import db
# 查询表结构
res = db.query_sql("PRAGMA table_info(blog)")
print("blog表所有字段：")
for item in res:
    print(item)