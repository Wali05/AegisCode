# expect: AEG-TAINT-SQL
@app.route("/u")
def u():
    name = request.args.get("name")
    q = "SELECT * FROM users WHERE name = '{}'".format(name)
    cur.execute(q)
    return "ok"
