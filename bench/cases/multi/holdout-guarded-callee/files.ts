const ROOT = path.resolve("uploads");
export async function readUpload(name: string) {
  const p = path.resolve(ROOT, name);
  if (!p.startsWith(ROOT + path.sep)) throw new Error("bad path");
  return fs.promises.readFile(p);
}
