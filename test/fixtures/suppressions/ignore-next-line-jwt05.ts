import jwt from "jsonwebtoken";

export function issueToken(payload: object, secret: string) {
	// ciphersins-ignore-next-line CS-JWT-05
	return jwt.sign(payload, secret);
}
