import jwt from "jsonwebtoken";

const token = "eyJ.test";
// ciphersins-ignore-next-line CS-JWT-01
const payload = jwt.decode(token);

export { payload };
