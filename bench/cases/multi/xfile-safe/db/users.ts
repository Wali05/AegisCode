export function findUser(name: string) {
  return pool.query("SELECT * FROM users WHERE name = $1", [name]);
}
