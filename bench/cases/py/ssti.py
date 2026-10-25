# expect: AEG-TAINT-SSTI
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<p>Hello " + name + "</p>")
