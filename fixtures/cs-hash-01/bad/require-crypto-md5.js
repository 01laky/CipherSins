const crypto = require("crypto");

function check(password, expected) {
	return crypto.createHash("md5").update(password).digest("hex");
}

module.exports = { check };
