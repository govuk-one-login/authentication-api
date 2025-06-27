package uk.gov.di.authentication.api;

import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.lambda.ClientRegistrationHandler;
import uk.gov.di.orchestration.shared.entity.Channel;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.PublicKeySource;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.REGISTER_CLIENT_REQUEST_RECEIVED;
import static uk.gov.di.orchestration.shared.entity.ServiceType.MANDATORY;
import static uk.gov.di.orchestration.shared.entity.ServiceType.OPTIONAL;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ClientRegistrationIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String VALID_PUBLIC_CERT =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    @BeforeEach
    void setup() {
        handler = new ClientRegistrationHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    private static Stream<Arguments> registrationRequestParams() {
        return Stream.of(
                Arguments.of(emptyList(), null, emptyList(), null, emptyList()),
                Arguments.of(
                        singletonList("http://localhost/post-redirect-logout"),
                        "http://back-channel.com",
                        List.of(ValidClaims.ADDRESS.getValue()),
                        String.valueOf(MANDATORY)),
                Arguments.of(
                        List.of(
                                "http://localhost/post-redirect-logout",
                                "http://localhost/post-redirect-logout-v2"),
                        "http://back-channel.com",
                        List.of(
                                ValidClaims.CORE_IDENTITY_JWT.getValue(),
                                ValidClaims.PASSPORT.getValue(),
                                ValidClaims.ADDRESS.getValue()),
                        String.valueOf(OPTIONAL)));
    }

    @ParameterizedTest
    @MethodSource("registrationRequestParams")
    void shouldCallRegisterEndpointAndReturn200(
            List<String> postlogoutUris,
            String backChannelLogoutUri,
            List<String> claims,
            String serviceType)
            throws Json.JsonException {
        var clientRequest =
                new ClientRegistrationRequest(
                        "The test client",
                        singletonList("http://localhost:1000/redirect"),
                        singletonList("test-client@test.com"),
                        PublicKeySource.STATIC.getValue(),
                        VALID_PUBLIC_CERT,
                        null,
                        singletonList("openid"),
                        postlogoutUris,
                        backChannelLogoutUri,
                        serviceType,
                        "https://test.com",
                        "public",
                        false,
                        claims,
                        ClientType.WEB.getValue(),
                        JWSAlgorithm.ES256.getName(),
                        Channel.WEB.getValue(),
                        false,
                        false,
                        "http://landing-page.com");

        var response = makeRequest(Optional.of(clientRequest), Map.of(), Map.of());

        var clientResponse =
                objectMapper.readValue(response.getBody(), ClientRegistrationResponse.class);

        Optional<ClientRegistry> client = clientStore.getClient(clientResponse.getClientId());

        assertThat(response, hasStatus(200));
        assertTrue(clientStore.clientExists(clientResponse.getClientId()));
        assertTrue(client.isPresent());
        assertTrue(client.get().isActive());
        assertThat(clientResponse.getClaims(), equalTo(claims));
        assertThat(clientResponse.getBackChannelLogoutUri(), equalTo(backChannelLogoutUri));
        assertThat(clientResponse.getClientType(), equalTo(ClientType.WEB.getValue()));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(REGISTER_CLIENT_REQUEST_RECEIVED));
    }
}
