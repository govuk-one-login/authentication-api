package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import uk.gov.di.authentication.shared.entity.ClientRegistry;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

class DynamoClientServiceTest {
    private static final ClientID CLIENT_ID = new ClientID();

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDbEnhancedClient dynamoDbEnhancedClient =
            mock(DynamoDbEnhancedClient.class);
    private DynamoClientService dynamoClientService;

    @BeforeEach
    void setup() {
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        dynamoClientService =
                spy(new DynamoClientService(configurationService, dynamoDbEnhancedClient));
    }

    @Test
    void shouldIdentifyATestUserJourney() {
        var client =
                generateClientRegistry(CLIENT_ID.toString())
                        .withTestClient(true)
                        .withTestClientEmailAllowlist(
                                List.of("test@test.com", "^(.+)@digital.cabinet-office.gov.uk$"));

        doReturn(Optional.of(client)).when(dynamoClientService).getClient(CLIENT_ID.toString());

        assertTrue(dynamoClientService.isTestJourney(CLIENT_ID.toString(), "test@test.com"));
        assertTrue(
                dynamoClientService.isTestJourney(
                        CLIENT_ID.toString(), "a.user1@digital.cabinet-office.gov.uk"));
        assertFalse(
                dynamoClientService.isTestJourney(
                        CLIENT_ID.toString(), "a.user1@digital1.cabinet-office.gov.uk"));
    }

    @Test
    void shouldIdentifyATestUserJourney_UserNotOnAllowList() {
        var client =
                generateClientRegistry(CLIENT_ID.toString())
                        .withTestClient(true)
                        .withTestClientEmailAllowlist(List.of("different-test@test.com"));

        doReturn(Optional.of(client)).when(dynamoClientService).getClient(CLIENT_ID.toString());

        assertFalse(dynamoClientService.isTestJourney(CLIENT_ID.toString(), "test@test.com"));
    }

    @Test
    void shouldIdentifyATestUserJourney_NoAllowlist() {
        var client = generateClientRegistry(CLIENT_ID.toString()).withTestClient(true);

        doReturn(Optional.of(client)).when(dynamoClientService).getClient(CLIENT_ID.toString());

        assertFalse(dynamoClientService.isTestJourney(CLIENT_ID.toString(), "test@test.com"));
    }

    @Test
    void shouldIdentifyATestUserJourney_MissingClient() {
        doReturn(Optional.empty()).when(dynamoClientService).getClient(CLIENT_ID.toString());

        assertFalse(dynamoClientService.isTestJourney(CLIENT_ID.toString(), "test@test.com"));
    }

    private ClientRegistry generateClientRegistry(String clientId) {
        return new ClientRegistry().withClientID(clientId);
    }
}
