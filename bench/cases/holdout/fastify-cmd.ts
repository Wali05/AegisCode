// expect: AEG-TAINT-CMD
fastify.post("/zip", async (request, reply) => {
  const { name } = request.body as { name: string };
  execSync(`zip -r ${name}.zip uploads/`);
  return reply.send({ ok: true });
});
