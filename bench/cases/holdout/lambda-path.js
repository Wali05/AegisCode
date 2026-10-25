// expect: AEG-TAINT-PATH
exports.handler = async (event) => {
  const name = event.queryStringParameters.file;
  return { statusCode: 200, body: fs.readFileSync("/var/task/static/" + name, "utf8") };
};
