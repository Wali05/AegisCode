// expect: none
const ROUTES: Record<string, string> = { home: "/", settings: "/settings" };
app.get("/login/done", (req, res) => {
  const key = String(req.query.to);
  res.redirect(ROUTES[key] ?? "/");
});
