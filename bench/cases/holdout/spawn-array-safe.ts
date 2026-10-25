// expect: none
app.post("/convert", (req, res) => {
  spawn("ffmpeg", ["-i", req.body.input, "out.mp4"]);
  res.end();
});
