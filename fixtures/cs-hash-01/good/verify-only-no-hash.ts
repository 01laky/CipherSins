export function verifyPassword(password: string, expected: string) {
	return password.length === expected.length;
}
