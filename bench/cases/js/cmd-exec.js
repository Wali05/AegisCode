// expect: AEG-TAINT-CMD
const { exec } = require("child_process");
app.post("/convert", (req, res) => {
  exec("convert " + req.body.file + " out.png", () => res.end());
});
