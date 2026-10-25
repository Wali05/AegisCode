// expect: AEG-TAINT-PATH
import fs from "node:fs/promises";
import path from "node:path";
app.get("/files/:name", async (req, res) => {
  res.send(await fs.readFile(path.join("/srv/uploads", req.params.name)));
});
