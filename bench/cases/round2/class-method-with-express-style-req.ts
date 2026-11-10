// expect: AEG-TAINT-SQL
class C {
  async show(req, res) {
    const row = await this.db.query("SELECT * FROM t WHERE id = " + req.params.id);
    res.json(row);
  }
}
