import {
  APIGatewayProxyEvent,
  APIGatewayProxyEventHeaders,
  APIGatewayProxyResult,
} from "aws-lambda";
import * as jose from "jose";
import { JWTPayload } from "jose";
import { getCookie, getOrCreatePersistentSessionId } from "../utils/cookie";
import crypto from "node:crypto";
import { downcaseHeaders } from "../utils/headers";
import { Session } from "../types/session";
import { getRedisClient, getSession } from "../services/redis";
import { ClientSession } from "../types/client-session";
import * as process from "node:process";
import { getPrivateKey } from "../utils/key";
import { renderGovukPage } from "../utils/page";
import {
  parseRequestParameters,
  RequestParameters,
} from "../services/request-parameters";
import { credentialTrustToEnum } from "../types/credential-trust";

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
  const form = `<h1 class="govuk-heading-xl">Orchestration stub</h1>
<form method='post'>
    <div class="govuk-form-group">
    <fieldset class="govuk-fieldset">
        <legend class="govuk-fieldset__legend govuk-fieldset__legend--l">
            <h2 class="govuk-fieldset__heading">
                Reauthentication
            </h2>
        </legend>
        <label for="reauthenticate" class="govuk-label">RP pairwise ID</label>
        <input name="reauthenticate" id="reauthenticate" class="govuk-input">
    </fieldset>
    </div>
    <div class="govuk-form-group">
    <fieldset class="govuk-fieldset">
        <legend class="govuk-fieldset__legend govuk-fieldset__legend--l">
            <h2 class="govuk-fieldset__heading">
                MFA
            </h2>
        </legend>
        <label for="level" class="govuk-label">Credential Trust Level</label>
        <div class="govuk-radios govuk-radios--inline" data-module="govuk-radios">
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="level" name="level" type="radio" value="Cl.Cm" checked>
                <label class="govuk-label govuk-radios__label" for="level">
                    Cl.Cm (2FA)
                </label>
            </div>
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="level-2" name="level" type="radio" value="Cl">
                <label class="govuk-label govuk-radios__label" for="level-2">
                    Cl (No 2FA)
                </label>
            </div>
        </div>
    </fieldset>
    </div>
    <div class="govuk-form-group">
        <fieldset class="govuk-fieldset">
            <legend class="govuk-fieldset__legend govuk-fieldset__legend--l">
                <h2 class="govuk-fieldset__heading">
                    Seamless login and uplift
                </h2>
            </legend>
            <div class="govuk-radios" data-module="govuk-radios">
                <div class="govuk-radios__item">
                    <input class="govuk-radios__input" id="authenticated" name="authenticated" type="radio" value="no"
                           checked>
                    <label class="govuk-label govuk-radios__label" for="authenticated">
                        Not authenticated
                    </label>
                </div>
                <div class="govuk-radios__item">
                    <input class="govuk-radios__input" id="authenticated-2" name="authenticated" type="radio"
                           value="yes" data-aria-controls="conditional-authenticated-2">
                    <label class="govuk-label govuk-radios__label" for="authenticated-2">
                        Authenticated
                    </label>
                    <div class="govuk-hint govuk-radios__hint">
                        You need to sign in at least once before selecting this option so that the email and internal
                        common subject identifier are set on the session
                    </div>
                </div>
                <div class="govuk-radios__conditional govuk-radios__conditional--hidden"
                     id="conditional-authenticated-2">
                    <div class="govuk-form-group govuk-radios" data-module="govuk-radios">
                        <div class="govuk-radios__item">
                            <input class="govuk-radios__input govuk-!-width-one-third" id="authenticated-level"
                                   name="authenticatedLevel" type="radio" value="Cl">
                            <label class="govuk-label govuk-radios__label" for="authenticated-level">
                                Low level
                            </label>
                        </div>
                        <div class="govuk-radios__item">
                            <input class="govuk-radios__input govuk-!-width-one-third" id="authenticated-level-2"
                                   name="authenticatedLevel" type="radio" value="Cl.Cm" checked>
                            <label class="govuk-label govuk-radios__label" for="authenticated-level-2">
                                Medium level
                            </label>
                        </div>
                    </div>
                </div>
            </div>
        </fieldset>
    </div>
    <button class="govuk-button">Submit</button>
</form>
`;
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "text/html",
    },
    body: renderGovukPage(form),
  };
};

const post = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  const form = parseRequestParameters(event.body);
  const gsCookie = await setUpSession(event.headers, form);
  const journeyId = gsCookie.split(".")[0];
  const signingPrivKey = await getPrivateKey();
  const payload = jarPayload(form, journeyId);
  const jws = await signRequestObject(payload, signingPrivKey);
  const jwe = await encryptRequestObject(jws, await sandpitFrontendPublicKey());

  const persistentSessionId = getOrCreatePersistentSessionId(event.headers);
  const cookieDomain =
    process.env.COOKIE_DOMAIN === "none"
      ? ""
      : `; Domain=${process.env.COOKIE_DOMAIN}`;
  return {
    statusCode: 302,
    multiValueHeaders: {
      Location: [
        `${process.env.AUTHENTICATION_FRONTEND_URL}authorize?request=${jwe}&response_type=code&client_id=orchestrationAuth`,
      ],
      "Set-Cookie": [
        `gs=${gsCookie}; max-age=3600${cookieDomain}`,
        `di-persistent-session-id=${persistentSessionId}; max-age=34190000${cookieDomain}`,
      ],
    },
    body: "",
  };
};

const jarPayload = (form: RequestParameters, journeyId: string): JWTPayload => {
  const claim = {
    userinfo: {
      salt: "",
      email: "",
      email_verified: "",
      phone_number: "",
      phone_number_verified: "",
      local_account_id: "",
      public_account_id: "",
      legacy_account_id: "",
    },
  };
  let payload: JWTPayload = {
    rp_client_id: process.env.RP_CLIENT_ID,
    rp_sector_host: "a.example.com",
    rp_redirect_uri: "https://a.example.com/redirect",
    rp_state: "state",
    client_name: "client",
    cookie_consent_shared: true,
    is_one_login_service: false,
    service_type: "essential",
    govuk_signin_journey_id: journeyId,
    confidence: form.confidence,
    state: "3",
    client_id: "orchestrationAuth",
    redirect_uri: `https://${process.env.STUB_DOMAIN}/orchestration-redirect`,
    claim: JSON.stringify(claim),
  };
  if (form["reauthenticate"] !== "") {
    payload["reauthenticate"] = form["reauthenticate"];
  }
  return payload;
};

const sandpitFrontendPublicKey = async () =>
  await jose.importSPKI(process.env.AUTH_PUB_KEY!, "RS256");

const signRequestObject = async (
  payload: JWTPayload,
  signingPrivKey: jose.KeyLike,
) => {
  return await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256" })
    .setIssuer("orchestrationAuth")
    .setAudience(process.env.AUTHENTICATION_FRONTEND_URL!!)
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

const setUpSession = async (
  headers: APIGatewayProxyEventHeaders,
  config: RequestParameters,
) => {
  const newSessionId = crypto.randomBytes(20).toString("base64url");
  const newClientSessionId = crypto.randomBytes(20).toString("base64url");
  await createNewClientSession(newClientSessionId, config);

  const existingGsCookie = getCookie(headers["cookie"], "gs");
  if (existingGsCookie) {
    const idParts = existingGsCookie.split(".");
    const sessionId = idParts[0];
    try {
      await renameExistingSession(sessionId, newSessionId, config);
    } catch (e) {
      await createNewSession(newSessionId, config);
    }
  } else {
    await createNewSession(newSessionId, config);
  }
  await attachClientSessionToSession(newClientSessionId, newSessionId);

  return `${newSessionId}.${newClientSessionId}`;
};

const createNewClientSession = async (
  id: string,
  config: RequestParameters,
) => {
  const client = await getRedisClient();
  const clientSession: ClientSession = {
    creation_time: new Date(),
    client_name: "Example RP",
    auth_request_params: {
      vtr: [`[${config.confidence}]`],
      scope: ["openid email phone"],
      response_type: ["code"],
      redirect_uri: [
        "https://rp-dev.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      ],
      state: ["dwG_gAlpIuRK-6FKReKEnoNUZdwgy8BUxYKUaXmIXeY"],
      prompt: ["none"],
      nonce: ["AJYiGSXv6euaffiuG5jMNgCwQW0ne7yuqDR9PrjsuvQ"],
      client_id: [process.env.RP_CLIENT_ID!!],
    },
    effective_vector_of_trust: {
      credential_trust_level: credentialTrustToEnum(config.confidence),
    },
  };
  await client.setEx(
    `client-session-${id}`,
    3600,
    JSON.stringify(clientSession),
  );
};

const createNewSession = async (id: string, config: RequestParameters) => {
  const session: Session = {
    session_id: id,
    code_request_count_map: {},
    authenticated: config.authenticated,
    current_credential_strength: credentialTrustToEnum(
      config.authenticatedLevel,
    ),
  };
  const client = await getRedisClient();
  await client.setEx(id, 3600, JSON.stringify(session));
};

const renameExistingSession = async (
  existingSessionId: string,
  newSessionId: string,
  config: RequestParameters,
) => {
  const client = await getRedisClient();
  const existingSession = await getSession(existingSessionId);
  await client.del(existingSessionId);
  existingSession.session_id = newSessionId;
  existingSession.authenticated = config.authenticated;
  existingSession.current_credential_strength = credentialTrustToEnum(
    config.authenticatedLevel,
  );
  await client.setEx(newSessionId, 3600, JSON.stringify(existingSession));
};

const attachClientSessionToSession = async (
  clientSessionId: string,
  sessionId: string,
) => {
  const client = await getRedisClient();
  const session = await getSession(sessionId);

  session.client_sessions ||= [];
  session.client_sessions.push(clientSessionId);

  await client.setEx(sessionId, 3600, JSON.stringify(session));
};
