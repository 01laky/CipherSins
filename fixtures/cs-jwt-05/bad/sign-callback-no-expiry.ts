import jwt from "jsonwebtoken";
export function issueToken(
	payload: object,
	secret: string,
	cb: jwt.SignCallback,
) {
	return jwt.sign(payload, secret, cb);
}
