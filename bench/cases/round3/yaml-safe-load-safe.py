# expect: none
@app.route("/config", methods=["POST"])
def config():
    cfg = yaml.safe_load(request.data)
    return jsonify(cfg)
