# expect: AEG-TAINT-DESER
@app.route("/load", methods=["POST"])
def load():
    return {"keys": list(pickle.loads(request.data))}
