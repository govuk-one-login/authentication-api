package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.lambda.ClientRegistrationHandler;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.DynamoHelper;

import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ClientRegistrationIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final String VALID_PUBLIC_CERT =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    @BeforeEach
    void setup() {
        handler = new ClientRegistrationHandler(configurationService);
    }

    @Test
    void shouldCallRegisterEndpointAndReturn200() throws JsonProcessingException {
        ClientRegistrationRequest clientRequest =
                new ClientRegistrationRequest(
                        "The test client",
                        singletonList("http://localhost:1000/redirect"),
                        singletonList("test-client@test.com"),
                        VALID_PUBLIC_CERT,
                        singletonList("openid"),
                        singletonList("http://localhost/post-redirect-logout"),
                        String.valueOf(ServiceType.MANDATORY),
                        "https://test.com",
                        "public");

        var response = makeRequest(Optional.of(clientRequest), Map.of(), Map.of());

        ClientRegistrationResponse clientResponse =
                objectMapper.readValue(response.getBody(), ClientRegistrationResponse.class);

        assertThat(response, hasStatus(200));
        assertTrue(DynamoHelper.clientExists(clientResponse.getClientId()));
    }
}
