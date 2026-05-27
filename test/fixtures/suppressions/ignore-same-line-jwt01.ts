import jwt from "jsonwebtoken";

const token = "eyJ.test";
const payload = jwt.decode(token); // ciphersins-ignore CS-JWT-01

export { payload };
