import process from "node:process";
import * as jose from "jose";

export const getPrivateKey = async () =>
  jose.importPKCS8(process.env.PRIVATE_KEY!, "RSA");
