const secret = process.env.JWT_SECRET ?? "dev-secret";

function readToken(token) {
	const payload = require("jsonwebtoken").decode(token);
	return require("jsonwebtoken").verify(token, secret) ?? payload;
}

module.exports = { readToken };
