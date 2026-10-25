# expect: AEG-TAINT-CMD
@app.route("/ping")
def ping():
    host = request.args["host"]
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)
