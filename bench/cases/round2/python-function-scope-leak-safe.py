# expect: none
def a():
    name = request.args.get("name")
    return name

def b(name):
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    os.system("echo " + name)
