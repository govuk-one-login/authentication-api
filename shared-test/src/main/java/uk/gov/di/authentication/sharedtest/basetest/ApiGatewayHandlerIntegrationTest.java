package uk.gov.di.authentication.sharedtest.basetest;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.shared.serialization.Json;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public abstract class ApiGatewayHandlerIntegrationTest
        extends HandlerIntegrationTest<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body, Map<String, String> headers, Map<String, String> queryString) {
        APIGatewayProxyRequestEvent request =
                constructRequest(
                        body, headers, queryString, Collections.emptyMap(), Collections.emptyMap());

        return handler.handleRequest(request, context);
    }

    protected APIGatewayProxyRequestEvent constructRequest(
            Optional<Object> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Map<String, String> pathParams,
            Map<String, Object> authorizerParams) {
        APIGatewayProxyRequestEvent request = baseApiRequest();
        request.withHeaders(headers)
                .withQueryStringParameters(queryString)
                .withPathParameters(pathParams);
        request.getRequestContext().setAuthorizer(authorizerParams);
        body.ifPresent(
                o -> {
                    if (o instanceof String) {
                        request.withBody((String) o);
                    } else {
                        try {
                            request.withBody(objectMapper.writeValueAsString(o));
                        } catch (Json.JsonException e) {
                            throw new RuntimeException("Could not serialise test body", e);
                        }
                    }
                });
        return request;
    }

    protected static APIGatewayProxyRequestEvent baseApiRequest() {
        return new APIGatewayProxyRequestEvent()
                .withRequestContext(
                        new ProxyRequestContext().withRequestId(UUID.randomUUID().toString()));
    }
}
