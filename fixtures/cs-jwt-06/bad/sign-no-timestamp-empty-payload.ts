import jwt from "jsonwebtoken";
export function issueToken(secret: string) {
	return jwt.sign({}, secret, { noTimestamp: true });
}
