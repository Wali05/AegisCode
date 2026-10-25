// expect: AEG-TAINT-SQL
function byEmail(email: string) {
  return `SELECT id FROM accounts WHERE email = '${email}'`;
}
router.post("/lookup", async (req, res) => {
  res.json(await pool.query(byEmail(req.body.email)));
});
