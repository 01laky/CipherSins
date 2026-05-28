import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

function verifyToken(token: string) {
	return jwt.verify(token, secret, { algorithms: ["HS256"] });
}

export function readToken(token: string) {
	const payload = jwt.decode(token);
	return verifyToken(token) ?? payload;
}
