import md5 from "md5";

export function hashPassword(password) {
	return md5(password);
}
