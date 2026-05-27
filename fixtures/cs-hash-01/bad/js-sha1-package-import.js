import sha1 from "js-sha1";

export function hashPassword(password) {
	return sha1(password);
}
