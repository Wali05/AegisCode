# expect: AEG-TAINT-PATH
@app.route("/download")
def download():
    name = request.args["name"]
    return send_file("/srv/files/" + name)
