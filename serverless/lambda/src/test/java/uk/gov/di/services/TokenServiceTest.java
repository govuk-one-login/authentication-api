package uk.gov.di.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TokenServiceTest {

    private ConfigurationService configurationService = mock(ConfigurationService.class);
    private RedisConnectionService redisConnectionService = mock(RedisConnectionService.class);
    private final TokenService tokenService =
            new TokenService(configurationService, redisConnectionService);
    private static final Subject SUBJECT = new Subject("some-subject");
    private static final String CLIENT_ID = "some-client-id";
    private static final List<String> SCOPES = List.of("openid", "email", "phone");
    private static final String BASE_URL = "http://example.com";

    @Test
    public void shouldGeneratedAccessTokenAndCallRedisToSave() {
        Optional<String> baseUrl = Optional.of(BASE_URL);
        when(configurationService.getBaseURL()).thenReturn(baseUrl);
        when(configurationService.getAccessTokenExpiry()).thenReturn(300L);

        AccessToken token = tokenService.generateAndStoreAccessToken(CLIENT_ID, SUBJECT, SCOPES);

        verify(redisConnectionService)
                .saveWithExpiry(token.toJSONString(), SUBJECT.toString(), 300L);
    }

    @Test
    public void shouldSuccessfullyGenerateIDtoken() throws ParseException {
        Optional<String> baseUrl = Optional.of(BASE_URL);
        when(configurationService.getBaseURL()).thenReturn(baseUrl);

        SignedJWT signedJWT = tokenService.generateIDToken("client-id", SUBJECT);

        assertEquals(BASE_URL, signedJWT.getJWTClaimsSet().getIssuer());
        assertEquals(SUBJECT.getValue(), signedJWT.getJWTClaimsSet().getClaim("sub"));
    }

    @Test
    public void shouldSuccessfullyValidatePrivateKeyJWTSignature() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT =
                new PrivateKeyJWT(
                        new ClientID("client-id"),
                        URI.create("http://localhost/token"),
                        JWSAlgorithm.RS256,
                        (RSAPrivateKey) keyPair.getPrivate(),
                        null,
                        null);
        String publicKey = Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded());
        assertTrue(
                tokenService.validatePrivateKeyJWTSignature(
                        publicKey, privateKeyJWT, "http://localhost/token"));
    }

    private KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException();
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
