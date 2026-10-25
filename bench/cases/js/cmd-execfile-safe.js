// expect: none
const { execFile } = require("child_process");
app.post("/convert", (req, res) => {
  execFile("convert", [req.body.file, "out.png"], () => res.end());
});
