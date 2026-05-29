import jwt from "jsonwebtoken";
export function issueToken(payload: object, secret: string) {
	return jwt.sign({ ...payload, nbf: Math.floor(Date.now() / 1000) }, secret);
}
