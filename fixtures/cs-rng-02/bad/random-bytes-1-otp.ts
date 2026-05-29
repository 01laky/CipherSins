import { randomBytes } from "crypto";
export function generateOtpCode() {
	return randomBytes(1).toString("hex");
}
