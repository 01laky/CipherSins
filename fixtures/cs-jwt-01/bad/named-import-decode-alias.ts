import { decode as parseJwt } from "jsonwebtoken";

export function readToken(token: string) {
	return parseJwt(token);
}
