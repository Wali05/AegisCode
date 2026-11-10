// expect: none
import path from "node:path";
import fs from "node:fs";
const ROOT = path.resolve("uploads");
app.get("/f", (req, res) => {
  const p = path.resolve(ROOT, req.query.name);
  if (!p.startsWith(ROOT + path.sep)) return res.sendStatus(400);
  res.send(fs.readFileSync(p, "utf8"));
});
