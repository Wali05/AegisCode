// expect: none
package api
func Get(db *sql.DB, id string) {
	db.QueryRow("SELECT * FROM users WHERE id = $1", id)
}
