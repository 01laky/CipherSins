import { randomBytes } from "crypto";
export function generateColor() {
	return randomBytes(4).toString("hex");
}
