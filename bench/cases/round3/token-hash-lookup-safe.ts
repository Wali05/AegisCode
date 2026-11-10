// expect: none
import crypto from "node:crypto";
app.post("/verify", async (req, res) => {
  const hash = crypto.createHash("sha256").update(String(req.body.token)).digest("hex");
  const rows = await db.query("SELECT user_id FROM tokens WHERE token_hash = '" + hash + "'");
  res.json({ valid: rows.length > 0 });
});
