import {
  APIGatewayProxyEvent,
  APIGatewayProxyEventHeaders,
  APIGatewayProxyResult,
} from "aws-lambda";
import * as jose from "jose";
import { JWTPayload } from "jose";
import * as querystring from "querystring";
import { ParsedUrlQuery } from "querystring";
import { getCookie, getOrCreatePersistentSessionId } from "../utils/cookie";
import crypto from "node:crypto";
import { downcaseHeaders } from "../utils/headers";
import { Session } from "../types/session";
import { getRedisClient, getSession } from "../services/redis";
import { ClientSession } from "../types/client-session";
import * as process from "node:process";

export const handler = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  downcaseHeaders(event);
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

  const gsCookie = await setUpSession(event.headers);
  const persistentSessionId = getOrCreatePersistentSessionId(event.headers);
  const cookieDomain =
    process.env.DOMAIN === "none" ? "" : `; Domain=${process.env.DOMAIN}`;
  return {
    statusCode: 302,
    multiValueHeaders: {
      Location: [`https://www.example.com/authorize?request=${jwe}`],
      "Set-Cookie": [
        `gs=${gsCookie}; max-age=3600${cookieDomain}`,
        `di-persistent-session-id=${persistentSessionId}; max-age=34190000${cookieDomain}`,
      ],
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

const setUpSession = async (headers: APIGatewayProxyEventHeaders) => {
  const newSessionId = crypto.randomBytes(20).toString("base64url");
  const newClientSessionId = crypto.randomBytes(20).toString("base64url");
  await createNewClientSession(newClientSessionId);

  const existingGsCookie = getCookie(headers["cookie"], "gs");
  if (existingGsCookie) {
    const idParts = existingGsCookie.split(".");
    const sessionId = idParts[0];
    await renameExistingSession(sessionId, newSessionId);
  } else {
    await createNewSession(newSessionId);
  }
  await attachClientSessionToSession(newClientSessionId, newSessionId);

  return `${newSessionId}.${newClientSessionId}`;
};

const createNewClientSession = async (id: string) => {
  const client = await getRedisClient();
  const clientSession: ClientSession = {
    creationTime: new Date(),
    clientName: "John",
  };
  await client.set(id, JSON.stringify(clientSession));
};

const createNewSession = async (id: string) => {
  const session: Session = { sessionId: id };
  const client = await getRedisClient();
  await client.set(id, JSON.stringify(session));
};

const renameExistingSession = async (
  existingSessionId: string,
  newSessionId: string,
) => {
  const client = await getRedisClient();
  const existingSession = await getSession(existingSessionId);
  await client.del(existingSessionId);
  existingSession.sessionId = newSessionId;
  await client.set(newSessionId, JSON.stringify(existingSession));
};

const attachClientSessionToSession = async (
  clientSessionId: string,
  sessionId: string,
) => {
  const client = await getRedisClient();
  const session = await getSession(sessionId);

  session.clientSessions ||= [];
  session.clientSessions.push(clientSessionId);

  await client.set(sessionId, JSON.stringify(session));
};
