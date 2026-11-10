// expect: AEG-TAINT-PATH
import fs from "node:fs";
app.get("/download", (req, res) => {
  fs.createReadStream(req.query.file).pipe(res);
});
