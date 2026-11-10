# expect: none
@app.route("/hi")
def hi():
    name = request.args.get("name", "")
    name = escape(name)
    return f"<h1>Hello {name}</h1>"
