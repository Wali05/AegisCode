// expect: AEG-TAINT-PATH
import fs from "node:fs/promises";
import path from "node:path";
app.get("/docs", async (req, res) => {
  const rel = path.normalize(String(req.query.p));
  res.send(await fs.readFile(path.join("/srv/docs", rel), "utf8"));
});
