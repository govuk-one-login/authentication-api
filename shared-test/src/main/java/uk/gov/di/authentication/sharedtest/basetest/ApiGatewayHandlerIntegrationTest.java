package uk.gov.di.authentication.sharedtest.basetest;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.ClientStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.extensions.RedisExtension;
import uk.gov.di.authentication.sharedtest.extensions.SnsTopicExtension;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.net.HttpCookie;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.Mockito.mock;

public abstract class ApiGatewayHandlerIntegrationTest {
    protected static final String LOCAL_ENDPOINT_FORMAT =
            "http://localhost:45678/restapis/%s/local/_user_request_";
    protected static final String LOCAL_API_GATEWAY_ID =
            Optional.ofNullable(System.getenv().get("API_GATEWAY_ID")).orElse("");
    protected static final String API_KEY =
            Optional.ofNullable(System.getenv().get("API_KEY")).orElse("");
    protected static final String FRONTEND_API_KEY =
            Optional.ofNullable(System.getenv().get("FRONTEND_API_KEY")).orElse("");
    public static final String ROOT_RESOURCE_URL =
            Optional.ofNullable(System.getenv().get("ROOT_RESOURCE_URL"))
                    .orElse(String.format(LOCAL_ENDPOINT_FORMAT, LOCAL_API_GATEWAY_ID));
    public static final String FRONTEND_ROOT_RESOURCE_URL =
            Optional.ofNullable(System.getenv().get("ROOT_RESOURCE_URL"))
                    .orElse(
                            String.format(
                                    LOCAL_ENDPOINT_FORMAT,
                                    Optional.ofNullable(
                                                    System.getenv().get("FRONTEND_API_GATEWAY_ID"))
                                            .orElse("")));
    protected static final ConfigurationService TEST_CONFIGURATION_SERVICE =
            new IntegrationTestConfigurationService();

    protected RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler;
    protected final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();
    protected final Context context = mock(Context.class);

    @RegisterExtension
    protected static final RedisExtension redis =
            new RedisExtension(ObjectMapperFactory.getInstance());

    @RegisterExtension
    protected static final UserStoreExtension userStore = new UserStoreExtension();

    @RegisterExtension
    protected static final ClientStoreExtension clientStore = new ClientStoreExtension();

    @RegisterExtension
    protected static final KmsKeyExtension auditSigningKey =
            new KmsKeyExtension(TEST_CONFIGURATION_SERVICE.getAuditSigningKeyAlias());

    @RegisterExtension
    protected static final SnsTopicExtension auditTopic = new SnsTopicExtension("local-events");

    @RegisterExtension
    protected static final SqsQueueExtension notificationsQueue =
            new SqsQueueExtension("local-email-notification-queue");

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body, Map<String, String> headers, Map<String, String> queryString) {
        return makeRequest(body, headers, queryString, Map.of());
    }

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Map<String, String> pathParams) {
        return makeRequest(body, headers, queryString, pathParams, Map.of());
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

    protected Map<String, String> constructHeaders(Optional<HttpCookie> cookie) {
        final Map<String, String> headers = new HashMap<>();
        cookie.ifPresent(c -> headers.put("Cookie", c.toString()));
        return headers;
    }

    protected Map<String, String> constructFrontendHeaders(String sessionId) {
        return constructFrontendHeaders(sessionId, Optional.empty());
    }

    protected Map<String, String> constructFrontendHeaders(
            String sessionId, String clientSessionId) {
        return constructFrontendHeaders(sessionId, Optional.of(clientSessionId));
    }

    protected Map<String, String> constructFrontendHeaders(
            String sessionId, Optional<String> clientSessionId) {
        var headers = new HashMap<String, String>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        clientSessionId.ifPresent(id -> headers.put("Client-Session-Id", id));
        return headers;
    }

    protected HttpCookie buildSessionCookie(String sessionID, String clientSessionID) {
        return new HttpCookie("gs", sessionID + "." + clientSessionID);
    }

    public static class IntegrationTestConfigurationService extends ConfigurationService {
        @Override
        public String getRedisHost() {
            return "localhost";
        }
    }
}
