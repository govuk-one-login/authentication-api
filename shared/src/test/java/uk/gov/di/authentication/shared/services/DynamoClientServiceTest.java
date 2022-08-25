package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
    private final AmazonDynamoDB dynamoDB = mock(AmazonDynamoDB.class);
    private DynamoClientService dynamoClientService;

    @BeforeEach
    void setup() {
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        dynamoClientService = spy(new DynamoClientService(configurationService, dynamoDB));
    }

    @Test
    void shouldIdentifyATestUserJourney() {
        var client =
                generateClientRegistry(CLIENT_ID.toString())
                        .setTestClient(true)
                        .setTestClientEmailAllowlist(List.of("test@test.com"));

        doReturn(Optional.of(client)).when(dynamoClientService).getClient(CLIENT_ID.toString());

        assertTrue(dynamoClientService.isTestJourney(CLIENT_ID.toString(), "test@test.com"));
    }

    @Test
    void shouldIdentifyATestUserJourney_UserNotOnAllowList() {
        var client =
                generateClientRegistry(CLIENT_ID.toString())
                        .setTestClient(true)
                        .setTestClientEmailAllowlist(List.of("different-test@test.com"));

        doReturn(Optional.of(client)).when(dynamoClientService).getClient(CLIENT_ID.toString());

        assertFalse(dynamoClientService.isTestJourney(CLIENT_ID.toString(), "test@test.com"));
    }

    @Test
    void shouldIdentifyATestUserJourney_NoAllowlist() {
        var client = generateClientRegistry(CLIENT_ID.toString()).setTestClient(true);

        doReturn(Optional.of(client)).when(dynamoClientService).getClient(CLIENT_ID.toString());

        assertFalse(dynamoClientService.isTestJourney(CLIENT_ID.toString(), "test@test.com"));
    }

    @Test
    void shouldIdentifyATestUserJourney_MissingClient() {
        doReturn(Optional.empty()).when(dynamoClientService).getClient(CLIENT_ID.toString());

        assertFalse(dynamoClientService.isTestJourney(CLIENT_ID.toString(), "test@test.com"));
    }

    private ClientRegistry generateClientRegistry(String clientId) {
        return new ClientRegistry().setClientID(clientId);
    }
}
