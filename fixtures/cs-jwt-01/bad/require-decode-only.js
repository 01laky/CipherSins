const jwt = require("jsonwebtoken");

function readToken(token) {
	return jwt.decode(token);
}

module.exports = { readToken };
