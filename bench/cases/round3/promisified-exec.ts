// expect: AEG-TAINT-CMD
import { exec } from "node:child_process";
import { promisify } from "node:util";
const execAsync = promisify(exec);
app.post("/thumbnail", async (req, res) => {
  const { stdout } = await execAsync(`convert ${req.body.file} -resize 200x200 out.png`);
  res.send(stdout);
});
