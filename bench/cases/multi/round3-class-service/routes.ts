import { UserService } from "./service";
const users = new UserService();
app.get("/users", async (req, res) => {
  res.json(await users.findByName(req.query.name));
});
