import jwt from "jsonwebtoken";

export function readHeader(token: string) {
	return jwt.decode(token, { complete: true });
}

export function readPayload(token: string) {
	return jwt.decode(token);
}
