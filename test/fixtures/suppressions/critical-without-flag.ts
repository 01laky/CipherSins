import jwt from "jsonwebtoken";

const token = "eyJ.test";
// ciphersins-ignore-next-line CS-JWT-03
jwt.verify(token, "secret", { algorithms: ["none"] });

export {};
