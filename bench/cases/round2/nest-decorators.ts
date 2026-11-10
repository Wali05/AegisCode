// expect: AEG-TAINT-SQL
@Controller("users")
export class UsersController {
  constructor(private readonly db: Db) {}
  @Get(":id")
  find(@Param("id") id: string, @Query("sort") sort: string) {
    return this.db.query(`SELECT * FROM users WHERE id = ${id} ORDER BY ${sort}`);
  }
}
