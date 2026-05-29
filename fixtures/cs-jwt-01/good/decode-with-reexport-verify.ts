import jwt from "jsonwebtoken";
export { verify } from "jsonwebtoken";

export function readToken(token: string) {
	const payload = jwt.decode(token);
	return payload;
}

export function validate(token: string) {
	return verify(token, process.env.JWT_SECRET!, { algorithms: ["HS256"] });
}
