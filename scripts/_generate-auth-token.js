#!/usr/bin/env node

const { v4: uuidv4 } = require("uuid");

const INTERNAL_COMMON_SUBJECT_ID = process.argv[2];
const CLIENT_ID = process.argv[3];
const KEY_ID = process.argv[4];

async function createJwt() {
  const issuedTimestamp = Math.floor(new Date().valueOf() / 1000);
  const payload = {
    sub: INTERNAL_COMMON_SUBJECT_ID,
    scope: ["openid", "email", "phone", "am"],
    iss: "https://example.com",
    exp: issuedTimestamp + 60 * 60 * 12,
    iat: issuedTimestamp,
    client_id: CLIENT_ID,
    jti: uuidv4(),
  };

  console.log("JWT Payload", payload);

  const protectedHeader = {
    alg: "ES256",
    kid: KEY_ID,
  };

  const encodedHeader = Buffer.from(JSON.stringify(protectedHeader)).toString(
    "base64url",
  );
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
    "base64url",
  );

  return `${encodedHeader}.${encodedPayload}`;
}

createJwt()
  .then((jwt) => console.log("Auth Token", jwt))
  .catch((err) => console.error("Error creating JWT:", err));
