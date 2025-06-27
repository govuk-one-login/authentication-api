package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.lambda.UpdateClientConfigHandler;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.ServiceType;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_RECEIVED;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdateClientConfigIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "client-id-1";
    private static final String VALID_PUBLIC_CERT =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    @BeforeEach
    void setup() {
        handler = new UpdateClientConfigHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldUpdateClientSuccessfully() throws Json.JsonException {
        clientStore.registerClient(
                CLIENT_ID,
                "The test client",
                singletonList("http://localhost:1000/redirect"),
                singletonList("test-client@test.com"),
                singletonList("openid"),
                VALID_PUBLIC_CERT,
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public");

        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        var expectedClientName = "new-client-name";
        updateRequest.setClientName(expectedClientName);
        var expectedRedirectUris = List.of("https://example.com/1", "https://example.com/2");
        updateRequest.setRedirectUris(expectedRedirectUris);
        var expectedContacts = List.of("test1@example.com", "test2@example.com");
        updateRequest.setContacts(expectedContacts);
        var expectedPublicKeySource = "STATIC";
        updateRequest.setPublicKeySource(expectedPublicKeySource);
        var expectedPublicKey =
                Base64.getMimeEncoder()
                        .encodeToString(GENERATE_RSA_KEY_PAIR().getPublic().getEncoded());
        updateRequest.setPublicKey(expectedPublicKey);
        var expectedScopes = List.of("openid", "email");
        updateRequest.setScopes(expectedScopes);
        var expectedPostLogoutRedirectUris =
                List.of("https://example.com/logout", "https://example.com/logged-out");
        updateRequest.setPostLogoutRedirectUris(expectedPostLogoutRedirectUris);
        var expectedServiceType = ServiceType.OPTIONAL.toString();
        updateRequest.setServiceType(expectedServiceType);
        var expectedJarValidationRequired = true;
        updateRequest.setJarValidationRequired(expectedJarValidationRequired);
        var expectedClaims =
                List.of(ValidClaims.ADDRESS.toString(), ValidClaims.PASSPORT.toString());
        updateRequest.setClaims(expectedClaims);
        var expectedSectorIdentifierUri = "https://test.example.com";
        updateRequest.setSectorIdentifierUri(expectedSectorIdentifierUri);
        var expectedClientType = ClientType.WEB.getValue();
        updateRequest.setClientType(expectedClientType);
        var expectedAcceptedLevelsOfConfidence =
                List.of(
                        LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                        LevelOfConfidence.HMRC200.getValue());
        updateRequest.setClientLoCs(expectedAcceptedLevelsOfConfidence);
        var expectedBackchannelLogoutUri = "https://api.example.com/backchannel/logout";
        updateRequest.setBackChannelLogoutUri(expectedBackchannelLogoutUri);
        var expectedLandingPageUrl = "https://example.com/landing-page";
        updateRequest.setLandingPageUrl(expectedLandingPageUrl);

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Map.of(),
                        Map.of(),
                        Map.of("clientId", CLIENT_ID));

        assertThat(response, hasStatus(200));
        ClientRegistrationResponse clientResponse =
                objectMapper.readValue(response.getBody(), ClientRegistrationResponse.class);

        assertThat(clientResponse.getClientId(), equalTo(CLIENT_ID));

        assertThat(clientResponse.getClientName(), equalTo(expectedClientName));
        assertThat(clientResponse.getRedirectUris(), equalTo(expectedRedirectUris));
        assertThat(clientResponse.getContacts(), equalTo(expectedContacts));
        assertThat(clientResponse.getScopes(), equalTo(expectedScopes));
        assertThat(
                clientResponse.getPostLogoutRedirectUris(),
                equalTo(expectedPostLogoutRedirectUris));
        assertThat(clientResponse.getServiceType(), equalTo(expectedServiceType));
        assertThat(
                clientResponse.getJarValidationRequired(), equalTo(expectedJarValidationRequired));
        assertThat(clientResponse.getClaims(), equalTo(expectedClaims));
        assertThat(clientResponse.getSectorIdentifierUri(), equalTo(expectedSectorIdentifierUri));
        assertThat(clientResponse.getClientType(), equalTo(expectedClientType));
        assertThat(clientResponse.getBackChannelLogoutUri(), equalTo(expectedBackchannelLogoutUri));
        assertThat(clientResponse.getLandingPageUrl(), equalTo(expectedLandingPageUrl));

        var persistedClient = clientStore.getClient(CLIENT_ID).orElseThrow();
        assertThat(persistedClient.getClientName(), equalTo(expectedClientName));
        assertThat(persistedClient.getRedirectUrls(), equalTo(expectedRedirectUris));
        assertThat(persistedClient.getContacts(), equalTo(expectedContacts));
        assertThat(persistedClient.getPublicKeySource(), equalTo(expectedPublicKeySource));
        assertThat(persistedClient.getPublicKey(), equalTo(expectedPublicKey));
        assertThat(persistedClient.getScopes(), equalTo(expectedScopes));
        assertThat(
                persistedClient.getPostLogoutRedirectUrls(),
                equalTo(expectedPostLogoutRedirectUris));
        assertThat(persistedClient.getServiceType(), equalTo(expectedServiceType));
        assertThat(
                persistedClient.isJarValidationRequired(), equalTo(expectedJarValidationRequired));
        assertThat(persistedClient.getClaims(), equalTo(expectedClaims));
        assertThat(persistedClient.getSectorIdentifierUri(), equalTo(expectedSectorIdentifierUri));
        assertThat(persistedClient.getClientType(), equalTo(expectedClientType));
        assertThat(persistedClient.getClientLoCs(), equalTo(expectedAcceptedLevelsOfConfidence));
        assertThat(
                persistedClient.getBackChannelLogoutUri(), equalTo(expectedBackchannelLogoutUri));
        assertThat(persistedClient.getLandingPageUrl(), equalTo(expectedLandingPageUrl));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(UPDATE_CLIENT_REQUEST_RECEIVED));
    }

    @Test
    void shouldRetainMaxAgeEnabledWhenUpdating() throws Json.JsonException {
        clientStore.registerClient(
                CLIENT_ID,
                "The test client",
                singletonList("http://localhost:1000/redirect"),
                singletonList("test-client@test.com"),
                singletonList("openid"),
                VALID_PUBLIC_CERT,
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                ClientType.WEB,
                false,
                List.of(),
                true,
                false);
        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        var expectedClientName = "new-client-name";
        updateRequest.setClientName(expectedClientName);

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Map.of(),
                        Map.of(),
                        Map.of("clientId", CLIENT_ID));

        assertThat(response, hasStatus(200));
        ClientRegistrationResponse clientResponse =
                objectMapper.readValue(response.getBody(), ClientRegistrationResponse.class);

        assertThat(clientResponse.getClientId(), equalTo(CLIENT_ID));

        assertThat(clientResponse.getClientName(), equalTo(expectedClientName));
        assertTrue(clientResponse.isMaxAgeEnabled());

        var persistedClient = clientStore.getClient(CLIENT_ID).orElseThrow();
        assertTrue(persistedClient.getMaxAgeEnabled());
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(UPDATE_CLIENT_REQUEST_RECEIVED));
    }

    @Test
    void shouldRetainPKCEEnforcedWhenUpdating() throws Json.JsonException {
        clientStore.registerClient(
                CLIENT_ID,
                "The test client",
                singletonList("http://localhost:1000/redirect"),
                singletonList("test-client@test.com"),
                singletonList("openid"),
                VALID_PUBLIC_CERT,
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                ClientType.WEB,
                false,
                List.of(),
                false,
                true);

        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        var expectedClientName = "new-client-name";
        updateRequest.setClientName(expectedClientName);

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Map.of(),
                        Map.of(),
                        Map.of("clientId", CLIENT_ID));

        assertThat(response, hasStatus(200));
        ClientRegistrationResponse clientResponse =
                objectMapper.readValue(response.getBody(), ClientRegistrationResponse.class);

        assertThat(clientResponse.getClientId(), equalTo(CLIENT_ID));

        assertThat(clientResponse.getClientName(), equalTo(expectedClientName));
        assertTrue(clientResponse.isPKCEEnforced());

        var persistedClient = clientStore.getClient(CLIENT_ID).orElseThrow();
        assertTrue(persistedClient.getPKCEEnforced());
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(UPDATE_CLIENT_REQUEST_RECEIVED));
    }

    @Test
    public void shouldReturn400WhenClientIsUnauthorized() {
        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        updateRequest.setClientName("new-client-name");

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Map.of(),
                        Map.of(),
                        Map.of("clientId", CLIENT_ID));

        assertThat(response, hasStatus(400));
        assertThat(
                response.getBody(),
                equalTo(OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(UPDATE_CLIENT_REQUEST_RECEIVED, UPDATE_CLIENT_REQUEST_RECEIVED));
    }
}
