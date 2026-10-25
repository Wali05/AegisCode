// expect: AEG-TAINT-SQL
router.get("/items", async (ctx) => {
  ctx.body = await knex.raw(`SELECT * FROM items WHERE owner = '${ctx.query.owner}'`);
});
