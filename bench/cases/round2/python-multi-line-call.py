# expect: AEG-TAINT-SQL
name = request.args.get("name")
cur.execute(
    "SELECT * FROM users WHERE name = '" + name + "'"
)
