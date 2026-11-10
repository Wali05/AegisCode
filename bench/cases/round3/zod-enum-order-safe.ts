// expect: none
import { z } from "zod";
const Query = z.object({ dir: z.enum(["asc", "desc"]) });
app.get("/posts", async (req, res) => {
  const { dir } = Query.parse(req.query);
  res.json(await db.query("SELECT * FROM posts ORDER BY created_at " + dir));
});
