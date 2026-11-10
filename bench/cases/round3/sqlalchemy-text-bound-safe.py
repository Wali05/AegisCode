# expect: none
@app.route("/user")
def user():
    row = db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": request.args["id"]}).first()
    return jsonify(dict(row))
