package uk.gov.di.orchestration.shared.dynamodb;

import com.nimbusds.openid.connect.sdk.SubjectType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ClientRegistryRateLimitServiceTest {
    private final ConfigurationService mockConfigService = mock(ConfigurationService.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private ClientRegistryRateLimitService clientRegistryRateLimitService;

    @BeforeEach
    void setup() {
        clientRegistryRateLimitService =
                new ClientRegistryRateLimitService(mockConfigService, dynamoDbClient);
    }

    @Test
    void getAllClientsGetsTheFirstPaginatedSetOfClients() {
        var client1 = generateUnmappedClientRegistryDynamoItem("test-client-1");
        var client2 = generateUnmappedClientRegistryDynamoItem("test-client-2");

        when(dynamoDbClient.scan(any(ScanRequest.class)))
                .thenReturn(ScanResponse.builder().items(client1, client2).build());

        var clients = clientRegistryRateLimitService.getAllClients();

        assertEquals(clients, List.of(client1, client2));
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
