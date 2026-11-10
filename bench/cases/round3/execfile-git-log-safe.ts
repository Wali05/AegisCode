// expect: none
import { execFile } from "node:child_process";
app.get("/log", (req, res) => {
  execFile("git", ["log", "-n", "20", "--author", String(req.query.author)], (err, stdout) => {
    if (err) return res.status(500).end();
    res.type("text/plain").send(stdout);
  });
});
