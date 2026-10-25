import { lookup } from "./db";
app.get("/l", async (req, res) => res.json(await lookup(req.query.k)));
