import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { downcaseHeaders } from "../utils/headers";
import { JWTPayload } from "jose";
import * as jose from "jose";
import { getPrivateKey } from "../utils/key";

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
  const clientAssertion = await buildClientAssertion(authCode);
  // const tokenResponse = getToken(clientAssertion);
  // const userInfo = getUserInfo(tokenResponse);

  return {
    statusCode: 200,
    body: JSON.stringify(clientAssertion),
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

const buildClientAssertion = async (authCode: string) => {
  let payload: JWTPayload = {};

  const privateKey = await getPrivateKey();
  return await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256" })
    .setIssuer("orchstub")
    .setSubject("orchstub")
    .setAudience("tokenurl")
    .setNotBefore("-1s")
    .setIssuedAt("-1s")
    .setExpirationTime("5m")
    .setJti("4")
    .sign(privateKey);
};
