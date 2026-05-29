import jwt from "jsonwebtoken";
export function issueToken(secret: string) {
	return jwt.sign({ sub: "user", exp: 9999999999 }, secret);
}
