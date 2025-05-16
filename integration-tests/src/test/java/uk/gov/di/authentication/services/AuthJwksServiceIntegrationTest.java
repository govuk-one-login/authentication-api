package uk.gov.di.authentication.services;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.net.MalformedURLException;
import java.net.URL;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class AuthJwksServiceIntegrationTest {
    private static JwksService jwksService;
    private static WireMockServer wireMockServer;
    private static URL testUrl;
    private static JWKSource<SecurityContext> jwkSource;

    @BeforeAll
    static void setUp() throws MalformedURLException {
        ConfigurationService configurationService = ConfigurationService.getInstance();
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMockServer.start();
        int port = wireMockServer.port();
        testUrl = new URL(String.format("http://localhost:%d/.well-known/jwks.json", port));
        configureFor("localhost", wireMockServer.port());
        jwksService =
                JwksService.getInstance(
                        configurationService, new KmsConnectionService(configurationService));

        jwkSource =
                JWKSourceBuilder.create(testUrl)
                        .retrying(true)
                        .refreshAheadCache(false)
                        .cache(true)
                        .rateLimited(false)
                        .build();
    }

    @AfterAll
    static void afterAll() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @Test
    void shouldCacheJwksResponse() {
        String ecKeyId = "test-key-ec";
        String rsaKeyId = "test-key-rsa";
        String jwksResponse =
                String.format(
                        """
                        {
                          "keys": [
                            {
                              "kty": "RSA",
                              "e": "AQAB",
                              "use": "enc",
                              "alg": "RS256",
                              "n": "modulus",
                              "kid": "%s"
                            },
                            {
                              "kty": "EC",
                              "use": "sig",
                              "crv": "P-256",
                              "x": "UPvU5NPmELrWiWSMVfDD7G8u3EJYryqPIZ46W9MAlRc",
                              "y": "r77F2-KPhpvTIGEWgt5SmavSvBUHCqWUxD6RG_FJHVk",
                              "alg": "ES256",
                              "kid": "%s"
                            }
                          ]
                        }""",
                        rsaKeyId, ecKeyId);

        wireMockServer.stubFor(
                get(urlPathMatching("/.well-known/jwks.json"))
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(jwksResponse)));

        JWK firstResult = jwksService.retrieveJwkFromJwkSource(jwkSource, rsaKeyId);
        assertInstanceOf(JWK.class, firstResult);

        JWK secondResult = jwksService.retrieveJwkFromJwkSource(jwkSource, rsaKeyId);
        assertInstanceOf(JWK.class, secondResult);

        verify(1, getRequestedFor(urlPathMatching("/.well-known/jwks.json")));
    }
}
