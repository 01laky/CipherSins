import crypto from "crypto";

const passwordHash = crypto.createHash("md5").update("x").digest("hex");

export { passwordHash };
