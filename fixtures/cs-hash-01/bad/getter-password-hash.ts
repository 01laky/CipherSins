import crypto from "crypto";

export class CredentialStore {
	get passwordHash(): string {
		return crypto.createHash("sha1").update("seed").digest("hex");
	}
}

void crypto;
