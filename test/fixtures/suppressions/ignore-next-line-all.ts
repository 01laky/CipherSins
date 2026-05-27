import jwt from "jsonwebtoken";

const token = "eyJ.test";
// ciphersins-ignore-next-line
const payload = jwt.decode(token);

export { payload };
