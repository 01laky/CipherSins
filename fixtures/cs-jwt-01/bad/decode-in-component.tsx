import jwt from "jsonwebtoken";

export function TokenViewer({ token }: { token: string }) {
	const payload = jwt.decode(token);
	return <pre>{JSON.stringify(payload)}</pre>;
}
