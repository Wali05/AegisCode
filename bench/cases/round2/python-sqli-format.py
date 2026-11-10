# expect: AEG-TAINT-SQL
@app.route("/u")
def u():
    name = request.args.get("name")
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return "ok"
