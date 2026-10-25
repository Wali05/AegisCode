// expect: AEG-TAINT-SQL
class Search {
  term = "";
  constructor(private db: Db) {}
  load(req: Request) { this.term = req.query.q; }
  run() { return this.db.query("SELECT * FROM t WHERE x = '" + this.term + "'"); }
}
