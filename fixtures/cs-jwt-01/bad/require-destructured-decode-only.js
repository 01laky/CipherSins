const { decode } = require("jsonwebtoken");

function readToken(token) {
	return decode(token);
}

module.exports = { readToken };
