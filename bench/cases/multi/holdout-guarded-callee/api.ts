import { readUpload } from "./files";
app.get("/f", async (req, res) => res.send(await readUpload(req.params.name)));
