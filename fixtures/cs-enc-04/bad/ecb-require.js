const crypto = require("crypto");
function encrypt(data, key, iv) {
	return crypto.createCipheriv("aes-128-ecb", key, iv);
}
module.exports = { encrypt };
