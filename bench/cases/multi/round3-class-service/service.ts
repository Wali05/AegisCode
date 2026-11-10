import { db } from "./db";
export class UserService {
  findByName(name: string) {
    return db.query("SELECT * FROM users WHERE name = '" + name + "'");
  }
}
