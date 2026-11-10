# expect: none
@app.route("/files")
def files():
    return send_from_directory(UPLOADS, request.args["f"])
