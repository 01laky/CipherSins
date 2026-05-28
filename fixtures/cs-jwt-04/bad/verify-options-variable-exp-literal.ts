import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";
const opts = { ignoreExpiration: true };

export function readToken(token: string) {
	return jwt.verify(token, secret, opts);
}
