// expect: none
import { exec } from "node:child_process";
app.post("/ping", (req, res) => {
  const host = req.body.host;
  if (!/^[a-z0-9.-]+$/i.test(host)) return res.status(400).end();
  exec(`ping -c 1 ${host}`, () => res.end());
});
