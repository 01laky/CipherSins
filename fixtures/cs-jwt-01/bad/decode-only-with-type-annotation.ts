import jwt from "jsonwebtoken";

interface JwtPayload {
	sub: string;
	exp?: number;
}

export function readToken(token: string): JwtPayload | null {
	const payload: JwtPayload | null = jwt.decode(token);
	return payload;
}
