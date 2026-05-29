import { scryptSync } from "crypto";
const cost = 8192;
export function hashPassword(password: string, salt: Buffer) {
	return scryptSync(password, salt, 64, {
		cost,
		blockSize: 8,
		parallelization: 1,
	});
}
