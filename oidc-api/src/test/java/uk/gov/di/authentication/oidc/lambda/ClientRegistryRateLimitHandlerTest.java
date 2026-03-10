package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.openid.connect.sdk.SubjectType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.dynamodb.ClientRegistryRateLimitService;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

public class ClientRegistryRateLimitHandlerTest {
    private ClientRegistryRateLimitHandler handler;
    private final ClientRegistryRateLimitService mockClientRegistryRateLimitService =
            mock(ClientRegistryRateLimitService.class);
    private Context mockContext = mock(Context.class);

    @BeforeEach
    void setup() {
        handler = new ClientRegistryRateLimitHandler(mockClientRegistryRateLimitService);
    }

    @Test
    void handleRequestGetsAllClientsAndUpdatesThem() {
        var client1 = generateUnmappedClientRegistryDynamoItem("test-client-1");
        var client2 = generateUnmappedClientRegistryDynamoItem("test-client-2");
        var client3 = generateUnmappedClientRegistryDynamoItem("test-client-3");
        var mockRateLimitServiceResult = List.of(client1, client2, client3);

        when(mockClientRegistryRateLimitService.getAllClients())
                .thenReturn(mockRateLimitServiceResult);

        var result = handler.handleRequest(new Object(), mockContext);

        assertEquals("Done!", result);
        verify(mockClientRegistryRateLimitService, times(1)).getAllClients();
        verify(mockClientRegistryRateLimitService, times(1))
                .updateClientsWithRateLimit(mockRateLimitServiceResult);
    }

    @Test
    void handleRequestRethrowsAnyErrorsThrownByGetAllClients() {
        doThrow(DynamoDbException.class).when(mockClientRegistryRateLimitService).getAllClients();

        assertThrows(
                RuntimeException.class, () -> handler.handleRequest(new Object(), mockContext));
        verify(mockClientRegistryRateLimitService, times(1)).getAllClients();
    }

    @Test
    void handleRequestRethrowsAnAnyErrorsThrownByUpdateClients() {
        var client1 = generateUnmappedClientRegistryDynamoItem("test-client-1");
        var client2 = generateUnmappedClientRegistryDynamoItem("test-client-2");
        var client3 = generateUnmappedClientRegistryDynamoItem("test-client-3");
        var mockRateLimitServiceResult = List.of(client1, client2, client3);

        when(mockClientRegistryRateLimitService.getAllClients())
                .thenReturn(mockRateLimitServiceResult);
        doThrow(DynamoDbException.class)
                .when(mockClientRegistryRateLimitService)
                .updateClientsWithRateLimit(mockRateLimitServiceResult);

        assertThrows(
                RuntimeException.class, () -> handler.handleRequest(new Object(), mockContext));
        verify(mockClientRegistryRateLimitService, times(1)).getAllClients();
        verify(mockClientRegistryRateLimitService, times(1))
                .updateClientsWithRateLimit(mockRateLimitServiceResult);
    }

    private Map<String, AttributeValue> generateUnmappedClientRegistryDynamoItem(String clientId) {
        return Map.ofEntries(
                Map.entry(
                        "ClientID",
                        AttributeValue.fromS(clientId != null ? clientId : "test-client")),
                Map.entry("ClientName", AttributeValue.fromS("test-client")),
                Map.entry("PublicKey", AttributeValue.fromS("example-key")),
                Map.entry(
                        "Scopes",
                        AttributeValue.fromL(
                                List.of(
                                        AttributeValue.fromS("openid"),
                                        AttributeValue.fromS("email"),
                                        AttributeValue.fromS("phone")))),
                Map.entry(
                        "RedirectUrls",
                        AttributeValue.fromL(List.of(AttributeValue.fromS("https://example.com")))),
                Map.entry(
                        "Contacts",
                        AttributeValue.fromL(List.of(AttributeValue.fromS("example@example.com")))),
                Map.entry(
                        "PostLogoutRedirectUrls",
                        AttributeValue.fromL(
                                List.of(AttributeValue.fromS("https://example.com/post-logout")))),
                Map.entry("ServiceType", AttributeValue.fromS("MANDATORY")),
                Map.entry("SectorIdentifierUri", AttributeValue.fromS("https://example.com")),
                Map.entry("SubjectType", AttributeValue.fromS(SubjectType.PAIRWISE.toString())));
    }
}
