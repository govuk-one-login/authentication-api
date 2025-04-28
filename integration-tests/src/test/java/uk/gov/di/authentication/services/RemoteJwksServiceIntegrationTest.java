package uk.gov.di.authentication.services;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.JwksServiceFailureReason;
import uk.gov.di.authentication.frontendapi.services.RemoteJwksService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.http.HttpClient;
import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RemoteJwksServiceIntegrationTest {
    private static WireMockServer wireMockServer;
    private static RemoteJwksService remoteJwksService;
    private static final ConfigurationService configurationService = new ConfigurationService();

    @BeforeAll
    static void setUp() {
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMockServer.start();
        int port = wireMockServer.port();
        String testUrl = String.format("http://localhost:%d/.well-known/jwks.json", port);
        configureFor("localhost", wireMockServer.port());

        HttpClient httpClient = HttpClient.newHttpClient();
        remoteJwksService = new RemoteJwksService(configurationService, testUrl, httpClient);
    }

    @AfterAll
    static void afterAll() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    static Stream<Arguments> keyTypes() {
        return Stream.of(Arguments.of(KeyType.RSA, "key1rsa"), Arguments.of(KeyType.EC, "key2ec"));
    }

    @ParameterizedTest
    @MethodSource("keyTypes")
    void shouldGetKeys(KeyType kty, String expectedKeyId) {
        String jwksResponse =
                """
                        {
                          "keys": [
                            {
                              "kty": "RSA",
                              "e": "AQAB",
                              "use": "enc",
                              "alg": "RS256",
                              "n": "modulus",
                              "kid": "key1rsa"
                            },
                            {
                              "kty": "EC",
                              "use": "sig",
                              "crv": "P-256",
                              "x": "UPvU5NPmELrWiWSMVfDD7G8u3EJYryqPIZ46W9MAlRc",
                              "y": "r77F2-KPhpvTIGEWgt5SmavSvBUHCqWUxD6RG_FJHVk",
                              "alg": "ES256",
                              "kid": "key2ec"
                            }
                          ]
                        }""";

        wireMockServer.stubFor(
                get(urlPathMatching("/.well-known/jwks.json"))
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(jwksResponse)));

        JWK jwk = remoteJwksService.getJwkByKeyType(kty).getSuccess();
        assertNotNull(jwk);
        assertEquals(kty, jwk.getKeyType());
        assertEquals(expectedKeyId, jwk.getKeyID());
    }

    @Test
    void shouldReturnParseFailureError() {
        String jwksResponse =
                """
                        {
                          "invalid": [
                            {
                              "invalid": "invalid",
                            },
                          ]
                        }""";

        wireMockServer.stubFor(
                get(urlPathMatching("/.well-known/jwks.json"))
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(jwksResponse)));

        var result = remoteJwksService.getJwkByKeyType(KeyType.EC);
        assertEquals(JwksServiceFailureReason.PARSE_FAILURE, result.getFailure());
    }
}
