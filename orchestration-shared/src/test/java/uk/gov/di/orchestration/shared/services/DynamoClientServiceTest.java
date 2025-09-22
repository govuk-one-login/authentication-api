package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.internal.matchers.apachecommons.ReflectionEquals;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.entity.ServiceType.MANDATORY;

class DynamoClientServiceTest extends BaseDynamoServiceTest<ClientRegistry> {
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name-one";
    private static final List<String> SCOPES = singletonList("openid");
    private static final String SERVICE_TYPE = String.valueOf(MANDATORY);
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

    @Test
    void emptyFieldsInUpdateRequestShouldHaveNoEffect() {
        var oldClient = generatePopulatedClientRegistry();
        var client = generatePopulatedClientRegistry();

        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        when(table.getItem((Key) any())).thenReturn(client);
        when(dynamoDbEnhancedClient.table(any(), eq(TableSchema.fromBean(ClientRegistry.class))))
                .thenReturn(table);
        dynamoClientService =
                spy(new DynamoClientService(configurationService, dynamoDbEnhancedClient));

        dynamoClientService.updateClient(CLIENT_ID.toString(), updateRequest);

        Assertions.assertTrue(new ReflectionEquals(oldClient).matches(client));
    }

    @Test
    void updateRequestShouldChangeValues() {
        var oldClient = generatePopulatedClientRegistry();
        var client = generateClientRegistry(CLIENT_ID.toString());

        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        updateRequest
                .setClientName(CLIENT_NAME)
                .setPublicKey("public-key")
                .setScopes(SCOPES)
                .setRedirectUris(singletonList("http://localhost/redirect"))
                .setContacts(singletonList("contant-name"))
                .setPostLogoutRedirectUris(singletonList("localhost/logout"))
                .setServiceType(SERVICE_TYPE)
                .setClientType(ClientType.WEB.getValue())
                .setIdentityVerificationSupported(true)
                .setClaims(List.of("claim"));

        when(table.getItem((Key) any())).thenReturn(client);
        when(dynamoDbEnhancedClient.table(any(), eq(TableSchema.fromBean(ClientRegistry.class))))
                .thenReturn(table);
        dynamoClientService =
                spy(new DynamoClientService(configurationService, dynamoDbEnhancedClient));

        dynamoClientService.updateClient(CLIENT_ID.toString(), updateRequest);
        Assertions.assertTrue(new ReflectionEquals(oldClient).matches(client));
    }

    private ClientRegistry generateClientRegistry(String clientId) {
        return new ClientRegistry().withClientID(clientId);
    }

    private ClientRegistry generatePopulatedClientRegistry() {
        return generateClientRegistry(CLIENT_ID.toString())
                .withClientName(CLIENT_NAME)
                .withPublicKey("public-key")
                .withScopes(SCOPES)
                .withRedirectUrls(singletonList("http://localhost/redirect"))
                .withContacts(singletonList("contant-name"))
                .withPostLogoutRedirectUrls(singletonList("localhost/logout"))
                .withServiceType(SERVICE_TYPE)
                .withClientType(ClientType.WEB.getValue())
                .withIdentityVerificationSupported(true)
                .withClaims(List.of("claim"));
    }
}
