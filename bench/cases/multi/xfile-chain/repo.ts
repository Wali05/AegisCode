export function run(sql: string) {
  return pool.query(sql);
}
