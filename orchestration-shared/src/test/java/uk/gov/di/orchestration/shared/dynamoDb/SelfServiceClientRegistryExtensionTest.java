package uk.gov.di.orchestration.shared.dynamoDb;

import com.nimbusds.openid.connect.sdk.SubjectType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbExtensionContext;
import software.amazon.awssdk.enhanced.dynamodb.extensions.WriteModification;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.orchestration.shared.dynamodb.SelfServiceClientRegistryExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.util.Collections.emptyList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.HIGH_LEVEL;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.LOW_LEVEL;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.MEDIUM_LEVEL;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.NONE;

class SelfServiceClientRegistryExtensionTest {

    private SelfServiceClientRegistryExtension selfServiceClientRegistryExtension;
    DynamoDbExtensionContext.BeforeWrite mockContext =
            mock(DynamoDbExtensionContext.BeforeWrite.class);

    @BeforeEach
    void setup() {
        selfServiceClientRegistryExtension = new SelfServiceClientRegistryExtension();
    }

    @Test
    void itReturnsImmediatelyIfNullItem() {
        when(mockContext.items()).thenReturn(null);

        WriteModification writeModification =
                selfServiceClientRegistryExtension.beforeWrite(mockContext);

        assertNull(writeModification.transformedItem());
    }

    @Test
    void itDoesNotModifyAnItemThatDoesNotContainTheClientLOCsField() {
        var client = generateRawClientRegistryEntry(null);
        when(mockContext.items()).thenReturn(client);

        WriteModification writeModification =
                selfServiceClientRegistryExtension.beforeWrite(mockContext);

        assertNull(writeModification.transformedItem());
    }

    @Test
    void itReturnsAnEmptyLOCIfTheClientContainsAP0LocValue() {
        var client = new HashMap<>(generateRawClientRegistryEntry(List.of(NONE.getValue())));
        when(mockContext.items()).thenReturn(client);

        WriteModification writeModification =
                selfServiceClientRegistryExtension.beforeWrite(mockContext);

        var expectedModifiedClient = new HashMap<>(client);
        expectedModifiedClient.put("ClientLoCs", AttributeValue.fromL(emptyList()));

        assertEquals(expectedModifiedClient, writeModification.transformedItem());
    }

    @Test
    void itReturnsAnEmptyLOCIfTheClientContainsAP2LocValue() {
        var client =
                new HashMap<>(generateRawClientRegistryEntry(List.of(MEDIUM_LEVEL.getValue())));
        when(mockContext.items()).thenReturn(client);

        WriteModification writeModification =
                selfServiceClientRegistryExtension.beforeWrite(mockContext);

        var expectedModifiedClient = new HashMap<>(client);
        expectedModifiedClient.put("ClientLoCs", AttributeValue.fromL(emptyList()));

        assertEquals(expectedModifiedClient, writeModification.transformedItem());
    }

    @Test
    void itReturnsDoesNotModifyAClientIfTheClientContainsAP1LocValue() {
        var client = new HashMap<>(generateRawClientRegistryEntry(List.of(LOW_LEVEL.getValue())));
        when(mockContext.items()).thenReturn(client);

        WriteModification writeModification =
                selfServiceClientRegistryExtension.beforeWrite(mockContext);

        assertNull(writeModification.transformedItem());
    }

    @Test
    void itReturnsDoesNotModifyAClientIfTheClientContainsAP3LocValue() {
        var client = new HashMap<>(generateRawClientRegistryEntry(List.of(HIGH_LEVEL.getValue())));
        when(mockContext.items()).thenReturn(client);

        WriteModification writeModification =
                selfServiceClientRegistryExtension.beforeWrite(mockContext);

        assertNull(writeModification.transformedItem());
    }

    private Map<String, AttributeValue> generateRawClientRegistryEntry(List<String> clientLocs) {
        var client =
                new HashMap<>(
                        Map.ofEntries(
                                Map.entry("ClientID", AttributeValue.fromS("test-client")),
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
                                        AttributeValue.fromL(
                                                List.of(
                                                        AttributeValue.fromS(
                                                                "https://example.com")))),
                                Map.entry(
                                        "Contacts",
                                        AttributeValue.fromL(
                                                List.of(
                                                        AttributeValue.fromS(
                                                                "example@example.com")))),
                                Map.entry(
                                        "PostLogoutRedirectUrls",
                                        AttributeValue.fromL(
                                                List.of(
                                                        AttributeValue.fromS(
                                                                "https://example.com/post-logout")))),
                                Map.entry("ServiceType", AttributeValue.fromS("MANDATORY")),
                                Map.entry(
                                        "SectorIdentifierUri",
                                        AttributeValue.fromS("https://example.com")),
                                Map.entry(
                                        "SubjectType",
                                        AttributeValue.fromS(SubjectType.PAIRWISE.toString()))));

        if (Objects.nonNull(clientLocs)) {
            client.put(
                    "ClientLoCs",
                    AttributeValue.fromL(clientLocs.stream().map(AttributeValue::fromS).toList()));
        }
        return client;
    }
}
