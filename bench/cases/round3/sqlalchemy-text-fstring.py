# expect: AEG-TAINT-SQL
@app.route("/user")
def user():
    name = request.args["name"]
    row = db.session.execute(text(f"SELECT * FROM users WHERE name = '{name}'")).first()
    return jsonify(dict(row))
