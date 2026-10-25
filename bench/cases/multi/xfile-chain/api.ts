import { search } from "./service";
app.get("/s", async (req, res) => res.json(await search(req.query.q)));
