import jwt from "jsonwebtoken";

function parseToken(token: string) {
	return jwt.decode(token);
}

export function readToken(token: string) {
	return parseToken(token);
}
