// expect: AEG-TAINT-PROTO
import _ from "lodash";
const settings = { theme: "light" };
app.patch("/settings", (req, res) => {
  _.merge(settings, req.body);
  res.json(settings);
});
