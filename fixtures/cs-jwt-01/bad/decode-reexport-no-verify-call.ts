import jwt from "jsonwebtoken";
export { verify } from "jsonwebtoken";

export function readToken(token: string) {
	const payload = jwt.decode(token);
	return payload;
}
