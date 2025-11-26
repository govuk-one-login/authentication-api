package uk.gov.di.authentication.oidc.services;

import com.nimbusds.openid.connect.sdk.SubjectType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.AdditionalAnswers;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.emptyMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ClientRegistryMigrationServiceTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private ClientRegistryMigrationService clientRegistryMigrationService;
    private final String env = "test";
    private final String fakeDynamoArn =
            " arn:aws:dynamodb:fake-region-south-2:123456789012:table-";

    @BeforeEach
    void setup() {
        when(configurationService.getEnvironment()).thenReturn(env);
        clientRegistryMigrationService =
                new ClientRegistryMigrationService(configurationService, false, dynamoDbClient);
    }

    @Test
    void getAllItemsShouldReturnEarlyWhenInitialRequestGetsAllItems() {
        when(dynamoDbClient.scan(any(ScanRequest.class)))
                .thenReturn(
                        ScanResponse.builder()
                                .lastEvaluatedKey(emptyMap())
                                .items(generateUnmappedClientRegistryDynamoItem())
                                .build());

        var clients = clientRegistryMigrationService.getAllClients();
        assertThat(clients.size(), equalTo(1));
        assertEquals(clients.get(0), generateUnmappedClientRegistryDynamoItem());
        verify(dynamoDbClient, times(1)).scan(any(ScanRequest.class));
    }

    @Test
    void throwsAnExceptionWhenScanningFails() {
        when(dynamoDbClient.scan(any(ScanRequest.class)))
                .thenThrow(new RuntimeException("Failed to scan DynamoDB Table"));

        assertThrows(RuntimeException.class, () -> clientRegistryMigrationService.getAllClients());
        verify(dynamoDbClient, times(1)).scan(any(ScanRequest.class));
    }

    @Test
    void throwsAnExceptionWhenPutItemThrows() {
        when(dynamoDbClient.putItem(any(PutItemRequest.class)))
                .thenThrow(new RuntimeException("Failed to put item to DynamoDB Table"));

        assertThrows(
                RuntimeException.class,
                () ->
                        clientRegistryMigrationService.putClientToDynamo(
                                generateUnmappedClientRegistryDynamoItem()));
        verify(dynamoDbClient, times(1)).putItem(any(PutItemRequest.class));
    }

    @Test
    void getAllItemsShouldFetchUntilEmptyLastEvaluatedKey() {
        var responses =
                List.of(
                        ScanResponse.builder()
                                .lastEvaluatedKey(
                                        generateUnmappedClientRegistryDynamoItem(
                                                "test-client-id-1"))
                                .items(generateUnmappedClientRegistryDynamoItem("test-client-id-1"))
                                .build(),
                        ScanResponse.builder()
                                .lastEvaluatedKey(
                                        generateUnmappedClientRegistryDynamoItem(
                                                "test-client-id-2"))
                                .items(generateUnmappedClientRegistryDynamoItem("test-client-id-2"))
                                .build(),
                        ScanResponse.builder()
                                .lastEvaluatedKey(emptyMap())
                                .items(generateUnmappedClientRegistryDynamoItem("test-client-id-3"))
                                .build());
        when(dynamoDbClient.scan(any(ScanRequest.class)))
                .thenAnswer(AdditionalAnswers.returnsElementsOf(responses));

        var clients = clientRegistryMigrationService.getAllClients();
        assertThat(clients.size(), equalTo(3));
        verify(dynamoDbClient, times(3)).scan(any(ScanRequest.class));
        assertEquals(clients.get(0), generateUnmappedClientRegistryDynamoItem("test-client-id-1"));
        assertEquals(clients.get(1), generateUnmappedClientRegistryDynamoItem("test-client-id-2"));
        assertEquals(clients.get(2), generateUnmappedClientRegistryDynamoItem("test-client-id-3"));
    }

    @Test
    void putItemShouldPutItemToTable() {
        clientRegistryMigrationService.putClientToDynamo(
                generateUnmappedClientRegistryDynamoItem());

        verify(dynamoDbClient)
                .putItem(
                        PutItemRequest.builder()
                                .item(generateUnmappedClientRegistryDynamoItem())
                                .tableName(env + "-client-registry")
                                .build());
    }

    @Test
    void passingFalseInConstructorFlagShouldUseTableNameWithoutArn() {
        when(configurationService.getDynamoArnPrefix()).thenReturn(Optional.of(fakeDynamoArn));
        clientRegistryMigrationService =
                new ClientRegistryMigrationService(configurationService, true, dynamoDbClient);

        clientRegistryMigrationService.putClientToDynamo(
                generateUnmappedClientRegistryDynamoItem());

        verify(dynamoDbClient)
                .putItem(
                        PutItemRequest.builder()
                                .item(generateUnmappedClientRegistryDynamoItem())
                                .tableName(env + "-client-registry")
                                .build());
    }

    @Test
    void passingFalseInConstructorFlagShouldAmendTableName() {
        when(configurationService.getDynamoArnPrefix()).thenReturn(Optional.of(fakeDynamoArn));
        clientRegistryMigrationService =
                new ClientRegistryMigrationService(configurationService, false, dynamoDbClient);

        clientRegistryMigrationService.putClientToDynamo(
                generateUnmappedClientRegistryDynamoItem());

        verify(dynamoDbClient)
                .putItem(
                        PutItemRequest.builder()
                                .item(generateUnmappedClientRegistryDynamoItem())
                                .tableName(fakeDynamoArn + "client-registry")
                                .build());
    }

    private Map<String, AttributeValue> generateUnmappedClientRegistryDynamoItem() {
        return generateUnmappedClientRegistryDynamoItem(null);
    }

    private Map<String, AttributeValue> generateUnmappedClientRegistryDynamoItem(String clientId) {
        return Map.ofEntries(
                Map.entry(
                        "clientID",
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
