# expect: AEG-TAINT-SSTI
@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return render_template_string(f"<h1>Hello {name}</h1>")
