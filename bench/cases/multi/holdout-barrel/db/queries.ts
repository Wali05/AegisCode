export function lookup(key: string) {
  return pool.query(`SELECT v FROM kv WHERE k = '${key}'`);
}
