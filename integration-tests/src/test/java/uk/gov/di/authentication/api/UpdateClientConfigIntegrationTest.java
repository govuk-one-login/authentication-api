package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.lambda.UpdateClientConfigHandler;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_RECEIVED;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdateClientConfigIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "client-id-1";
    private static final String VALID_PUBLIC_CERT =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    @BeforeEach
    void setup() {
        handler = new UpdateClientConfigHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    public void shouldUpdateClientNameSuccessfully() throws JsonProcessingException {
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
                true);

        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        updateRequest.setClientName("new-client-name");

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Map.of(),
                        Map.of(),
                        Map.of("clientId", CLIENT_ID));

        assertThat(response, hasStatus(200));
        ClientRegistrationResponse clientResponse =
                objectMapper.readValue(response.getBody(), ClientRegistrationResponse.class);
        assertThat(clientResponse.getClientName(), equalTo("new-client-name"));
        assertThat(clientResponse.getClientId(), equalTo(CLIENT_ID));

        assertEventTypesReceived(auditTopic, List.of(UPDATE_CLIENT_REQUEST_RECEIVED));
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

        assertEventTypesReceived(
                auditTopic,
                List.of(UPDATE_CLIENT_REQUEST_RECEIVED, UPDATE_CLIENT_REQUEST_RECEIVED));
    }
}
