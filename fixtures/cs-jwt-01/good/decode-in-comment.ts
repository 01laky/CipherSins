import jwt from "jsonwebtoken";

// jwt.decode(token) should not be flagged when only in a comment

export function readToken(token: string) {
	return token;
}
