import { sign as jwtSign } from "jsonwebtoken";
export function issueToken(payload: object, secret: string) {
	return jwtSign(payload, secret, { noTimestamp: true });
}
