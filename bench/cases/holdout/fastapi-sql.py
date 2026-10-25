# expect: AEG-TAINT-SQL
@app.get("/search")
def search(q: str, request: Request):
    term = request.query_params["q"]
    rows = conn.execute("SELECT * FROM docs WHERE title LIKE '%" + term + "%'")
    return rows.fetchall()
