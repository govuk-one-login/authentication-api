import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import * as jose from "jose";
import { JWTPayload } from "jose";
import * as querystring from "querystring";
import { ParsedUrlQuery } from "querystring";

export const handler = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  const method = event.httpMethod.toUpperCase();
  switch (method) {
    case "GET":
      return get(event);
    case "POST":
      return post(event);
    default:
      return {
        statusCode: 405,
        body: JSON.stringify({
          message: "Method not allowed: " + method,
        }),
      };
  }
};

const get = (event: APIGatewayProxyEvent): APIGatewayProxyResult => {
  const form = `<html>
<body><h1>Hello world</h1>
<form action='/' method='post'>
    <label for="reauthenticate">Reauthenticate (RP pairwise ID)</label>
    <input name="reauthenticate" id="reauthenticate">
    <button>submit</button>
</form>
</body>
</html>`;
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "text/html",
    },
    body: form,
  };
};

const post = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  const form = querystring.parse(event.body || "");
  const { publicKey: signingPubKey, privateKey: signingPrivKey } =
    await jose.generateKeyPair("ES256");
  const payload = jarPayload(form);
  const jws = await signRequestObject(payload, signingPrivKey);
  const jwe = await encryptRequestObject(jws, await sandpitFrontendPublicKey());

  return {
    statusCode: 302,
    headers: {
      Location: `https://www.example.com/authorize?request=${jwe}`,
    },
    body: "",
  };
};

const jarPayload = (form: ParsedUrlQuery): JWTPayload => {
  let payload: JWTPayload = {
    rp_client_id: "a",
    rp_sector_host: "a.example.com",
    rp_redirect_uri: "https://a.example.com/redirect",
    rp_state: "state",
    client_name: "client",
    cookie_consent_shared: true,
    is_one_login_service: false,
    service_type: "essential",
    govuk_signin_journey_id: "7",
    confidence: "Cl",
    state: "3",
    client_id: "orchstub",
    redirect_uri: "http://localhost:3000/callback",
    claims: {
      salt: null,
    },
  };
  if (form["reauthenticate"] !== "") {
    payload["reauthenticate"] = form["reauthenticate"];
  }
  return payload;
};

const sandpitFrontendPublicKey = async () =>
  await jose.importSPKI(
    `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs41htFRe62BIfwQZ0OCT
g5p2NHAekvIAJaNb6ZkLuLXYdLBax+2c9f4ALTrltmLMBpgtS6VQg2zO8UmSE4bX
+Nhaw2nf3/VRBIlAi2NiD4cUIwNtxIx5qpBeDxb+YR7NuTJ0nFq6u6jv34RB1RWE
J1sEOiv9aSPEt6eK8TGL6uZbPGU8CKJuWwPfW1ko/lyuM1HG0G/KAZ8DaLJzOMWX
+2aZatj9RHtOCtGxwMrZlU4n/O1gbVPBfXx9RugTi0W4upmeNFR5CsC+WgENkr0v
pXEyIW7edR6lDsSYzJI+yurVFyt82Bn7Vo2x5CIoLiH/1ZcKaApNU02/eK/gMBf+
EwIDAQAB
-----END PUBLIC KEY-----`,
    "RS256",
  );

const signRequestObject = async (
  payload: JWTPayload,
  signingPrivKey: jose.KeyLike,
) => {
  return await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256" })
    .setIssuedAt()
    .setIssuer("urn:example:issuer")
    .setAudience("urn:example:audience")
    .setNotBefore("-1s")
    .setIssuedAt("-1s")
    .setExpirationTime("2h")
    .setJti("4")
    .sign(signingPrivKey);
};

const encryptRequestObject = async (jws: string, encPubKey: jose.KeyLike) =>
  await new jose.CompactEncrypt(new TextEncoder().encode(jws))
    .setProtectedHeader({ cty: "JWT", alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(encPubKey);
