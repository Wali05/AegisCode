# expect: none
@app.route("/item")
def item():
    item_id = int(request.args["id"])
    cur.execute("SELECT * FROM items WHERE id = " + str(item_id))
    return jsonify(cur.fetchone())
