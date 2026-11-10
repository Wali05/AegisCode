// expect: none
app.get("/users/:id", async (req, res) => {
  const upstream = await fetch(`${process.env.USERS_API}/v1/users/${encodeURIComponent(req.params.id)}`);
  res.status(upstream.status).json(await upstream.json());
});
