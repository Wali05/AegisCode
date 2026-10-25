const media = require("./lib/media");
app.post("/thumb", (req, res) => { media.thumbnail(req.body.path); res.end(); });
