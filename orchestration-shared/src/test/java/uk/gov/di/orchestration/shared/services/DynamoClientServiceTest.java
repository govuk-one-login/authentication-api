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
import uk.gov.di.orchestration.shared.entity.ManualUpdateClientRegistryRequest;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.entity.ServiceType.MANDATORY;
import static uk.gov.di.orchestration.shared.entity.ServiceType.OPTIONAL;

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
    void emptyFieldsInUpdateSSEClientShouldHaveNoEffect() {
        var oldClient = generatePopulatedClientRegistry();
        var clientToBeUpdated = generatePopulatedClientRegistry();
        when(table.getItem((Key) any())).thenReturn(clientToBeUpdated);
        when(dynamoDbEnhancedClient.table(any(), eq(TableSchema.fromBean(ClientRegistry.class))))
                .thenReturn(table);
        dynamoClientService =
                spy(new DynamoClientService(configurationService, dynamoDbEnhancedClient));

        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        var updatedClient =
                dynamoClientService.updateSSEClient(CLIENT_ID.toString(), updateRequest);

        Assertions.assertTrue(new ReflectionEquals(oldClient).matches(updatedClient));
    }

    @Test
    void updateSSEClientShouldChangeValues() {
        var oldClient = generatePopulatedClientRegistry();
        when(table.getItem((Key) any())).thenReturn(oldClient);
        when(dynamoDbEnhancedClient.table(any(), eq(TableSchema.fromBean(ClientRegistry.class))))
                .thenReturn(table);
        dynamoClientService =
                spy(new DynamoClientService(configurationService, dynamoDbEnhancedClient));

        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        updateRequest
                .setClientName("new-client-name")
                .setPublicKey("new-public-key")
                .setScopes(singletonList("new-openid"))
                .setRedirectUris(singletonList("http://localhost/new-redirect"))
                .setContacts(singletonList("new-contact-name"))
                .setPostLogoutRedirectUris(singletonList("localhost/new-logout"))
                .setServiceType(String.valueOf(OPTIONAL))
                .setClientType(ClientType.APP.getValue())
                .setIdentityVerificationSupported(false)
                .setClaims(List.of("new-claim"));

        var updatedClient =
                dynamoClientService.updateSSEClient(CLIENT_ID.toString(), updateRequest);

        assertThat(oldClient.getClientID(), equalTo(updatedClient.getClientID()));
        assertThat(updatedClient.getClientName(), equalTo("new-client-name"));
        assertThat(updatedClient.getPublicKey(), equalTo("new-public-key"));
        assertThat(updatedClient.getScopes(), equalTo(singletonList("new-openid")));
        assertThat(
                updatedClient.getRedirectUrls(),
                equalTo((singletonList("http://localhost/new-redirect"))));
        assertThat(updatedClient.getContacts(), equalTo(singletonList("new-contact-name")));
        assertThat(
                updatedClient.getPostLogoutRedirectUrls(),
                equalTo(singletonList("localhost/new-logout")));
        assertThat(updatedClient.getServiceType(), equalTo(String.valueOf(OPTIONAL)));
        assertThat(updatedClient.getClientType(), equalTo(ClientType.APP.getValue()));
        assertFalse(updatedClient.isIdentityVerificationSupported());
        assertThat(updatedClient.getClaims(), equalTo(List.of("new-claim")));
    }

    @Test
    void manualUpdateClientShouldChangeValues() {
        var oldClient = generatePopulatedClientRegistry();
        when(table.getItem((Key) any())).thenReturn(oldClient);
        when(dynamoDbEnhancedClient.table(any(), eq(TableSchema.fromBean(ClientRegistry.class))))
                .thenReturn(table);
        dynamoClientService =
                spy(new DynamoClientService(configurationService, dynamoDbEnhancedClient));

        ManualUpdateClientRegistryRequest updateRequest =
                new ManualUpdateClientRegistryRequest(CLIENT_ID.toString(), "1");

        var updatedClient =
                dynamoClientService.manualUpdateClient(CLIENT_ID.toString(), updateRequest);

        assertThat(oldClient.getClientID(), equalTo(updatedClient.getClientID()));
        assertThat(updatedClient.getRateLimit(), equalTo(1));
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
                .withContacts(singletonList("contact-name"))
                .withPostLogoutRedirectUrls(singletonList("localhost/logout"))
                .withServiceType(SERVICE_TYPE)
                .withClientType(ClientType.WEB.getValue())
                .withIdentityVerificationSupported(true)
                .withClaims(List.of("claim"));
    }
}
