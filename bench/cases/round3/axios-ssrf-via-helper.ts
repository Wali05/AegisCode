// expect: AEG-TAINT-SSRF
import axios from "axios";
async function fetchPreview(url: string) {
  const res = await axios.get(url, { timeout: 5000 });
  return res.data;
}
app.post("/preview", async (req, res) => {
  res.json(await fetchPreview(req.body.url));
});
