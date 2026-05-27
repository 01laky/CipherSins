function decode(token: string) {
	return token.split(".")[1];
}

export function readToken(token: string) {
	return decode(token);
}
