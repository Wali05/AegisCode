const { exec } = require("child_process");
function thumbnail(file) {
  exec("convert " + file + " -resize 64x64 thumb.png");
}
module.exports = { thumbnail };
