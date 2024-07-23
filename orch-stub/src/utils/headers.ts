import { APIGatewayProxyEvent } from "aws-lambda";

/**
 * The headers in the AWS Lambda event are case sensitive and preserve the case
 * from the browser. This varies according to browser and HTTP 1 v.s 2
 *
 * This script adds lowercase versions of all headers to the array to simplify
 * later code.
 */
export function downcaseHeaders(event: APIGatewayProxyEvent) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if (!(event as any).headersFixed) {
    const headers = Object.keys(event.headers);
    for (const key of headers) {
      event.headers[key.toLowerCase()] = event.headers[key];
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (event as any).headersFixed = true;
  }
}
