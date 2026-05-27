import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	const payload = jwt.decode(token);

	if (payload) {
		function validate() {
			return jwt.verify(token, secret);
		}

		return validate();
	}

	return payload;
}
