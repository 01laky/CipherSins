import jwt from "jsonwebtoken";
export function issueToken(payload: object, secret: string) {
	return jwt.sign(payload, secret, { noTimestamp: true });
}
