import render from "./render";
app.get("/r", (req, res) => res.send(render(req.query.name)));
