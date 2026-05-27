export function hashPassword(password: string) {
	function createHash(_algo: string) {
		return { update: () => ({ digest: () => "x" }) };
	}
	return createHash("md5");
}
