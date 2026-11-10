# expect: none
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(os.path.join(UPLOADS, secure_filename(f.filename)))
    return "ok"
