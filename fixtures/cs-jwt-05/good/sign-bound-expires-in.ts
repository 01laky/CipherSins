import jwt from "jsonwebtoken";
const expiresIn = "2h";
export function issueToken(payload: object, secret: string) {
	return jwt.sign(payload, secret, { expiresIn });
}
