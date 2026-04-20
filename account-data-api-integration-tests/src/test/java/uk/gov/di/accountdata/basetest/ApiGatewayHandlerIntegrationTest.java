package uk.gov.di.accountdata.basetest;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.Mockito.mock;

public abstract class ApiGatewayHandlerIntegrationTest {

    protected RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler;

    protected final Context context = mock(Context.class);
    protected final Json objectMapper = SerializationService.getInstance();

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<String> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Map<String, String> pathParams) {
        String requestId = UUID.randomUUID().toString();
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        request.withHeaders(headers)
                .withQueryStringParameters(queryString)
                .withPathParameters(pathParams)
                .withRequestContext(
                        new APIGatewayProxyRequestEvent.ProxyRequestContext()
                                .withRequestId(requestId));
        body.ifPresent(request::withBody);

        return handler.handleRequest(request, context);
    }

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<String> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Map<String, String> pathParams,
            Map<String, Object> authorizerParams) {
        String requestId = UUID.randomUUID().toString();
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        var requestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext().withRequestId(requestId);
        requestContext.setAuthorizer(authorizerParams);
        request.withHeaders(headers)
                .withQueryStringParameters(queryString)
                .withPathParameters(pathParams)
                .withRequestContext(requestContext);
        body.ifPresent(request::withBody);

        return handler.handleRequest(request, context);
    }
}
