# expect: AEG-TAINT-SQL
@app.get("/items/{item_id}")
def read(item_id: str, q: str = None):
    cur.execute(f"SELECT * FROM items WHERE id = {item_id}")
    return {}
