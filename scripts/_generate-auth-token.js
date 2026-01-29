#!/usr/bin/env node

const { KMSClient, SignCommand } = require("@aws-sdk/client-kms");
const asn1 = require("asn1.js");
const { v4: uuidv4 } = require("uuid");

const kmsClient = new KMSClient({ region: "eu-west-2" });

const INTERNAL_COMMON_SUBJECT_ID = process.argv[2];
const CLIENT_ID = process.argv[3];
const KEY_ID = process.argv[4];

async function signWithKMS(message) {
  const command = new SignCommand({
    KeyId: KEY_ID,
    Message: message,
    MessageType: "RAW",
    SigningAlgorithm: "ECDSA_SHA_256",
  });

  const response = await kmsClient.send(command);
  return Buffer.from(response.Signature);
}

function derToRs(derSignature) {
  // ASN.1 DER decoder for ECDSA signature
  const EcdsaSigAsnParse = asn1.define("EcdsaSig", function () {
    this.seq().obj(this.key("r").int(), this.key("s").int());
  });

  const { r, s } = EcdsaSigAsnParse.decode(derSignature, "der");

  const uintLength = 32; // For P-256 curve, r and s are 32 bytes each
  return Buffer.concat([
    r.toArrayLike(Buffer, "be", uintLength),
    s.toArrayLike(Buffer, "be", uintLength),
  ]);
}

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
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const derSignature = await signWithKMS(Buffer.from(signingInput));
  const rsSignature = derToRs(derSignature);

  return `${signingInput}.${Buffer.from(rsSignature).toString("base64url")}`;
}

createJwt()
  .then((jwt) => {
    console.log("Auth Token:");
    console.log("Bearer", jwt);
  })
  .catch((err) => console.error("Error creating JWT:", err));
