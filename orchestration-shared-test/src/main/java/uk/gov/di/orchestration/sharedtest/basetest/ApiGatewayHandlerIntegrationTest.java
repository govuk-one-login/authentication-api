package uk.gov.di.orchestration.sharedtest.basetest;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.orchestration.shared.serialization.Json;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public abstract class ApiGatewayHandlerIntegrationTest
        extends HandlerIntegrationTest<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body, Map<String, String> headers, Map<String, String> queryString) {
        return makeRequest(
                body,
                headers,
                queryString,
                Collections.emptyMap(),
                Collections.emptyMap(),
                Optional.empty());
    }

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Optional<String> httpMethod) {
        return makeRequest(
                body,
                headers,
                queryString,
                Collections.emptyMap(),
                Collections.emptyMap(),
                httpMethod);
    }

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Map<String, String> pathParams) {
        return makeRequest(
                body, headers, queryString, pathParams, Collections.emptyMap(), Optional.empty());
    }

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Map<String, String> pathParams,
            Map<String, Object> authorizerParams) {
        return makeRequest(
                body, headers, queryString, pathParams, authorizerParams, Optional.empty());
    }

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Map<String, String> pathParams,
            Map<String, Object> authorizerParams,
            Optional<String> httpMethod) {
        String requestId = UUID.randomUUID().toString();
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        request.withHeaders(headers)
                .withQueryStringParameters(queryString)
                .withPathParameters(pathParams)
                .withHttpMethod(httpMethod.orElse(null))
                .withRequestContext(
                        new APIGatewayProxyRequestEvent.ProxyRequestContext()
                                .withRequestId(requestId));
        request.getRequestContext().setAuthorizer(authorizerParams);
        body.ifPresent(
                o -> {
                    if (o instanceof String string) {
                        request.withBody(string);
                    } else {
                        try {
                            request.withBody(objectMapper.writeValueAsString(o));
                        } catch (Json.JsonException e) {
                            throw new RuntimeException("Could not serialise test body", e);
                        }
                    }
                });

        return handler.handleRequest(request, context);
    }
}
