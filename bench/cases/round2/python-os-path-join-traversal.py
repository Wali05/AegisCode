# expect: AEG-TAINT-PATH
@app.route("/f")
def f():
    name = request.args.get("name")
    return send_file(os.path.join(UPLOADS, name))
