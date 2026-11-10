// expect: AEG-TAINT-PATH
import path from "node:path";
import fs from "node:fs";
app.get("/f", (req, res) => {
  const p = path.join(__dirname, "uploads", req.query.name);
  res.send(fs.readFileSync(p, "utf8"));
});
