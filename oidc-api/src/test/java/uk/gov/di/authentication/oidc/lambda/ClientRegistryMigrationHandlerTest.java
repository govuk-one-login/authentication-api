package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.openid.connect.sdk.SubjectType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.oidc.services.ClientRegistryMigrationService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class ClientRegistryMigrationHandlerTest {
    private final ClientRegistryMigrationService authClientRegistryMigrationService =
            mock(ClientRegistryMigrationService.class);
    private final ClientRegistryMigrationService orchClientRegistryMigrationService =
            mock(ClientRegistryMigrationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Context mockContext = mock(Context.class);
    private ClientRegistryMigrationHandler clientRegistryMigrationHandler;

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ClientRegistryMigrationHandler.class);

    @BeforeEach
    void setup() {
        clientRegistryMigrationHandler =
                new ClientRegistryMigrationHandler(
                        configurationService,
                        authClientRegistryMigrationService,
                        orchClientRegistryMigrationService);
    }

    @Test
    void itDoesNotExecuteDataTransferWhenOrchClientRegistryIsEnabled() {
        when(configurationService.isOrchClientRegistryEnabled()).thenReturn(true);

        var response = clientRegistryMigrationHandler.handleRequest(null, mockContext);
        assertThat(
                response,
                equalTo(
                        "Cannot invoke Migrate client registry handler as Orch Client Registry is enabled"));
        verifyNoInteractions(authClientRegistryMigrationService);
        verifyNoInteractions(orchClientRegistryMigrationService);
    }

    @Test
    void itReadsFromAuthTableAndWritesToOrchTableAndLogsAHash() {
        when(authClientRegistryMigrationService.getAllClients())
                .thenReturn(
                        List.of(
                                generateUnmappedClientRegistryDynamoItem("test-client-1"),
                                generateUnmappedClientRegistryDynamoItem("test-client-2")));

        when(orchClientRegistryMigrationService.getAllClients())
                .thenReturn(
                        List.of(
                                generateUnmappedClientRegistryDynamoItem("test-client-1"),
                                generateUnmappedClientRegistryDynamoItem("test-client-2")));

        var response = clientRegistryMigrationHandler.handleRequest(null, mockContext);

        verify(authClientRegistryMigrationService).getAllClients();
        verify(orchClientRegistryMigrationService, times(2)).putClientToDynamo(anyMap());

        assertThat(
                logging.events(), hasItem(withMessageContaining("Found 2 clients in Auth table")));
        assertThat(logging.events(), hasItem(withMessageContaining("Auth client registry hash")));
        assertThat(
                logging.events(), hasItem(withMessageContaining("Found 2 clients in Orch table")));
        assertThat(logging.events(), hasItem(withMessageContaining("Orch client registry hash")));
        assertThat(response, equalTo("Finished"));
    }

    @Test
    void itShouldSortClientsBeforeHashingToEnsureHashComparisonIsOnlyDeterminedByContents() {
        var clientsInOrder =
                List.of(
                        generateUnmappedClientRegistryDynamoItem("test-client-id-1"),
                        generateUnmappedClientRegistryDynamoItem("test-client-id-2"),
                        generateUnmappedClientRegistryDynamoItem("test-client-id-3"),
                        generateUnmappedClientRegistryDynamoItem("test-client-id-4"));

        var unOrderedClients =
                List.of(
                        generateUnmappedClientRegistryDynamoItem("test-client-id-3"),
                        generateUnmappedClientRegistryDynamoItem("test-client-id-4"),
                        generateUnmappedClientRegistryDynamoItem("test-client-id-1"),
                        generateUnmappedClientRegistryDynamoItem("test-client-id-2"));

        assertEquals(
                clientRegistryMigrationHandler.hashListOfClients(clientsInOrder),
                clientRegistryMigrationHandler.hashListOfClients(unOrderedClients));
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
