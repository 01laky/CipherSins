import { decode } from "jsonwebtoken";

export function readToken(token: string) {
	return decode(token);
}
