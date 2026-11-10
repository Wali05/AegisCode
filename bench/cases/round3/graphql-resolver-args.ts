// expect: AEG-TAINT-SQL
export const resolvers = {
  Query: {
    user: async (_parent, args, ctx) => {
      const rows = await ctx.db.query("SELECT * FROM users WHERE email = '" + args.email + "'");
      return rows[0];
    },
  },
};
