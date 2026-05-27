import sha1 from "sha1";

export function hashPassword(password) {
	return sha1(password);
}
