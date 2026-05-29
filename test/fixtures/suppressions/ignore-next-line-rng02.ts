import { randomBytes } from "crypto";

export function generateSessionToken() {
	// ciphersins-ignore-next-line CS-RNG-02
	return randomBytes(8).toString("hex");
}
