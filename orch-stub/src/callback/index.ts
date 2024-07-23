import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { downcaseHeaders } from "../utils/headers";

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
  return {
    statusCode: 200,
    body: "ok",
  };
};
