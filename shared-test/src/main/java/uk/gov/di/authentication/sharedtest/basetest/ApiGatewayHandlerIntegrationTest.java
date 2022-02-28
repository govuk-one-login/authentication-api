package uk.gov.di.authentication.sharedtest.basetest;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public abstract class ApiGatewayHandlerIntegrationTest
        extends HandlerIntegrationTest<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body, Map<String, String> headers, Map<String, String> queryString) {
        return makeRequest(body, headers, queryString, Collections.emptyMap());
    }

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Map<String, String> pathParams) {
        return makeRequest(body, headers, queryString, pathParams, Collections.emptyMap());
    }

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Map<String, String> pathParams,
            Map<String, Object> authorizerParams) {
        String requestId = UUID.randomUUID().toString();
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        request.withHeaders(headers)
                .withQueryStringParameters(queryString)
                .withPathParameters(pathParams)
                .withRequestContext(
                        new APIGatewayProxyRequestEvent.ProxyRequestContext()
                                .withRequestId(requestId));
        request.getRequestContext().setAuthorizer(authorizerParams);
        body.ifPresent(
                o -> {
                    if (o instanceof String) {
                        request.withBody((String) o);
                    } else {
                        try {
                            request.withBody(objectMapper.writeValueAsString(o));
                        } catch (JsonProcessingException e) {
                            throw new RuntimeException("Could not serialise test body", e);
                        }
                    }
                });

        return handler.handleRequest(request, context);
    }
}
