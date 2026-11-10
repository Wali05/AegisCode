// expect: AEG-TAINT-CODE
import vm from "node:vm";
app.post("/eval", (req, res) => {
  const result = vm.runInNewContext(req.body.code, { Math });
  res.json({ result });
});
