# expect: none
@app.route("/users")
def users():
    name = request.args.get("name")
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    return jsonify(cur.fetchall())
