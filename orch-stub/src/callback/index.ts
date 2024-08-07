import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { downcaseHeaders } from "../utils/headers";
import * as jose from "jose";
import { JWTPayload } from "jose";
import { getPrivateKey } from "../utils/key";
import { renderGovukPage } from "../utils/page";
import { getCookie } from "../utils/cookie";
import { getSession } from "../services/redis";

const TOKEN_URL = `${process.env.AUTHENTICATION_BACKEND_URL}token`;
const USER_INFO_URL = `${process.env.AUTHENTICATION_BACKEND_URL}userinfo`;

export const handler = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  downcaseHeaders(event);
  const method = event.httpMethod.toUpperCase();
  switch (method) {
    case "GET":
      return get(event);
    default:
      return {
        statusCode: 405,
        body: JSON.stringify({
          message: "Method not allowed: " + method,
        }),
      };
  }
};

const get = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  const authCode = getAuthCode(event);
  const clientAssertion = await buildClientAssertion();
  const tokenResponse = await getToken(authCode, clientAssertion);
  const userInfo = await getUserInfo(tokenResponse);

  const gsCookie = getCookie(event.headers["cookie"], "gs");
  const sessionId = gsCookie!.split(".")[0];
  const session = await getSession(sessionId);

  const content = `<script defer src="https://unpkg.com/pretty-json-custom-element/index.js"></script>
<dl class="govuk-summary-list">
    <div class="govuk-summary-list__row">
        <dt class="govuk-summary-list__key">
            Token
        </dt>
        <dd class="govuk-summary-list__value">
            ${tokenResponse}
        </dd>
    </div>
    <div class="govuk-summary-list__row">
        <dt class="govuk-summary-list__key">
            User Info
        </dt>
        <dd class="govuk-summary-list__value">
            <pretty-json>
                ${JSON.stringify(userInfo)}
            </pretty-json>
        </dd>
    </div>
    <div class="govuk-summary-list__row">
        <dt class="govuk-summary-list__key">
            Session
        </dt>
        <dd class="govuk-summary-list__value">
            <pretty-json>
                ${JSON.stringify(session)}
            </pretty-json>
        </dd>
    </div>
</dl>
<a href="/" role="button" draggable="false" class="govuk-button" data-module="govuk-button">
  Start again
</a>
    `;
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "text/html",
    },
    body: renderGovukPage(content),
  };
};

function getAuthCode(event: APIGatewayProxyEvent) {
  const queryStringParameters = event.queryStringParameters;
  if (queryStringParameters === null) {
    throw new Error("No queryStringParameters provided");
  }
  const authCode = queryStringParameters["code"];
  if (authCode === undefined) {
    throw new Error("No authCode provided");
  }
  return authCode;
}

const buildClientAssertion = async () => {
  let payload: JWTPayload = {};

  const privateKey = await getPrivateKey();
  return await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256" })
    .setIssuer("orchestrationAuth")
    .setSubject("orchestrationAuth")
    .setAudience(TOKEN_URL)
    .setNotBefore("-1s")
    .setIssuedAt("-1s")
    .setExpirationTime("5m")
    .setJti("4")
    .sign(privateKey);
};

const getToken = async (authCode: string, clientAssertion: string) => {
  const tokenUrl = new URL(TOKEN_URL);

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: authCode,
    client_assertion_type:
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: clientAssertion,
    redirect_uri: "",
    client_id: "orchestrationAuth",
  });

  const response = await fetch(tokenUrl, { method: "POST", body });
  if (!response.ok) {
    throw new Error(
      `Error while fetching token. Status code: ${response.status} Message: ${await response.text()}`,
    );
  }

  const tokenResponse: TokenResponse = await response.json();
  return tokenResponse.access_token;
};

const getUserInfo = async (accessToken: string) => {
  const userInfoUrl = new URL(USER_INFO_URL);
  const response = await fetch(userInfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    throw new Error(
      `Error while fetching user info. Status code: ${response.status} Message: ${await response.text()}`,
    );
  }

  return response.json();
};

type TokenResponse = {
  access_token: string;
};
