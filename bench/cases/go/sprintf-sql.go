// expect: AEG-GO-002
package api
func Get(db *sql.DB, id string) {
	db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}
