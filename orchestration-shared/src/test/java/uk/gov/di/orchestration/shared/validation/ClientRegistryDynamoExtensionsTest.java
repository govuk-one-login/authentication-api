package uk.gov.di.orchestration.shared.validation;

import com.nimbusds.openid.connect.sdk.SubjectType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbExtensionContext;
import software.amazon.awssdk.enhanced.dynamodb.extensions.ReadModification;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

public class ClientRegistryDynamoExtensionsTest {
    private final String clientId = "test-client";

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ClientRegistryDynamoExtensions.class);

    private ClientRegistryDynamoExtensions clientRegistryDynamoExtensions;
    DynamoDbExtensionContext.AfterRead mockContext = mock(DynamoDbExtensionContext.AfterRead.class);

    @BeforeEach
    void setup() {
        clientRegistryDynamoExtensions = new ClientRegistryDynamoExtensions();
        assertThat(logging.events(), not(hasItem(withMessageContaining(clientId))));
    }

    @Test
    void itDoesNotModifyAClientAndDoesNotLogWhenAllFieldsAreCorrect() {
        var client = generateRawClientRegistryEntry();
        when(mockContext.items()).thenReturn(client);

        ReadModification readModification = clientRegistryDynamoExtensions.afterRead(mockContext);

        assertEquals(client, readModification.transformedItem());
        assertEquals(0, logging.events().size());
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        String.format(
                                                "Unknown key: * present in client with ID: %s",
                                                clientId)))));
    }

    @Test
    void itDoesNotModifyAClientAndLogsAWarnForAnUnknownField() {
        var client = new HashMap<>(generateRawClientRegistryEntry());
        // Incorrect casing on URL, should be LandingPageUrl
        var invalidKey = "LandingPageURL";
        client.put(invalidKey, AttributeValue.fromS("https://example.com/landing-page"));
        when(mockContext.items()).thenReturn(client);

        ReadModification readModification = clientRegistryDynamoExtensions.afterRead(mockContext);

        assertEquals(client, readModification.transformedItem());
        assertEquals(1, logging.events().size());
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                String.format(
                                        "Unknown key: %s present in client with ID: %s",
                                        invalidKey, clientId))));
    }

    @Test
    void itDoesNotModifyAClientAndLogsAWarnFoMultipleUnknownFields() {
        var client = new HashMap<>(generateRawClientRegistryEntry());
        // Incorrect casing on URL, should be LandingPageUrl
        var invalidKey = "LandingPageURL";
        client.put(invalidKey, AttributeValue.fromS("https://example.com/landing-page"));

        var invalidKey2 = "PostLogoutRedirectURLs";
        client.put(
                invalidKey2,
                AttributeValue.fromL(
                        List.of(AttributeValue.fromS("https://example.com/post-logout"))));

        when(mockContext.items()).thenReturn(client);

        ReadModification readModification = clientRegistryDynamoExtensions.afterRead(mockContext);

        assertEquals(client, readModification.transformedItem());
        assertEquals(2, logging.events().size());
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                String.format(
                                        "Unknown key: %s present in client with ID: %s",
                                        invalidKey, clientId))));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                String.format(
                                        "Unknown key: %s present in client with ID: %s",
                                        invalidKey2, clientId))));
    }

    private Map<String, AttributeValue> generateRawClientRegistryEntry() {
        return Map.ofEntries(
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
