// expect: AEG-TAINT-SQL
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
router.get(
  "/orders",
  asyncHandler(async (req, res) => {
    const rows = await db.query("SELECT * FROM orders WHERE status = '" + req.query.status + "'");
    res.json(rows);
  })
);
