// expect: AEG-TAINT-SQL
class ProductService {
  constructor(private db) {}
  search(term: string) {
    return this.db.query("SELECT * FROM products WHERE name LIKE '%" + term + "%'");
  }
}
class ProductController {
  constructor(private service: ProductService) {}
  async list(req, res) {
    res.json(await this.service.search(req.query.q));
  }
}
