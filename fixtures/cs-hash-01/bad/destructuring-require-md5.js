const { createHash } = require("crypto");

function hashPassword(password) {
	return createHash("md5").update(password).digest("hex");
}

module.exports = { hashPassword };
