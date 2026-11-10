# expect: AEG-TAINT-SSRF
@app.route("/fetch", methods=["POST"])
def fetch():
    data = request.get_json()
    resp = requests.get(data["url"], timeout=5)
    return resp.text
