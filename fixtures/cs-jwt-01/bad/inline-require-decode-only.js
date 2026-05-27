function readHeader(token) {
	return require("jsonwebtoken").decode(token, { complete: true });
}

function readPayload(token) {
	return require("jsonwebtoken").decode(token);
}

module.exports = { readHeader, readPayload };
