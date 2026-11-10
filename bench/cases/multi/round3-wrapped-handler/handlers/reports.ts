import { execSync } from "node:child_process";
export function exportReport(req, res) {
  const out = execSync("./bin/export --format " + req.query.format);
  res.type("application/octet-stream").send(out);
}
