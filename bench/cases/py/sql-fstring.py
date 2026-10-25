# expect: AEG-TAINT-SQL
@app.route("/users")
def users():
    name = request.args.get("name")
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return jsonify(cur.fetchall())
