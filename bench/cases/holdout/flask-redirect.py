# expect: AEG-TAINT-REDIRECT
@app.route("/out")
def out():
    target = request.args.get("to")
    return redirect(target)
