// expect: AEG-TAINT-CMD
import { exec } from "child_process";
app.get("/", (req, res) => {
  exec(`git log --author=${req.query.a}`, (e, out) => res.send(out));
});
