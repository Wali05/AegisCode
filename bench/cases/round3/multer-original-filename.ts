// expect: AEG-TAINT-PATH
import fs from "node:fs";
import path from "node:path";
const UPLOAD_DIR = path.resolve("uploads");
app.post("/upload", upload.single("file"), (req, res) => {
  const dest = path.join(UPLOAD_DIR, req.file.originalname);
  fs.writeFileSync(dest, req.file.buffer);
  res.json({ ok: true });
});
