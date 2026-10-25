import { findUser } from "../db/users";
app.get("/u", async (req, res) => res.json(await findUser(req.query.name)));
