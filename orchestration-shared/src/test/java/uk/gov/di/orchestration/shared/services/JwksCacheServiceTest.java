package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.shared.utils.JwksUtils;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils.generateRsaKeyPair;

// QualityGateUnitTest
class JwksCacheServiceTest extends BaseDynamoServiceTest<JwksCacheItem> {
    private static final String JWKS_URL = "http://localhost/.well-known/jwks.json";
    private static final String KEY_ID_1 = "test-enc-key-1";
    private static final String KEY_ID_2 = "test-enc-key-2";
    private static final JWK JWK_1 = createPublicJwk(KEY_ID_1);
    private static final JWK JWK_2 = createPublicJwk(KEY_ID_2);
    private static final int expiryInSeconds = 100;
    private static final long VALID_TTL =
            Instant.now().plusSeconds(expiryInSeconds).getEpochSecond();
    private static final MockedStatic<JwksUtils> jwksUtilsMockedStatic =
            Mockito.mockStatic(JwksUtils.class);
    private JwksCacheService jwksCacheServiceSpy;

    @BeforeEach
    void setup() throws MalformedURLException {
        JwksCacheService jwksCacheService =
                new JwksCacheService(dynamoDbClient, table, configurationService);
        jwksCacheServiceSpy = Mockito.spy(jwksCacheService);
        URL testJwksUrl = new URL(JWKS_URL);
        when(configurationService.getIPVJwksUrl()).thenReturn(testJwksUrl);
        when(configurationService.getDocAppJwksUrl()).thenReturn(testJwksUrl);
        when(configurationService.getJwkCacheExpirationInSeconds()).thenReturn(expiryInSeconds);
    }

    @AfterAll
    static void afterAll() {
        if (jwksUtilsMockedStatic != null) {
            jwksUtilsMockedStatic.close();
        }
    }

    // QualityGateRegressionTest
    @Test
    void getOrGenerateIpvJwksCacheItemReturnsJwksCacheWithValidTtl() {
        withValidJwksCache();
        var jwksCacheItem = jwksCacheServiceSpy.getOrGenerateIpvJwksCacheItem();
        assertThat(jwksCacheItem.getKeyId(), equalTo(KEY_ID_1));
        assertThat(jwksCacheItem.getTimeToLive(), equalTo(VALID_TTL));
    }

    // QualityGateRegressionTest
    @Test
    void getOrGenerateIpvJwksCacheItemReturnsFirstJwksCache() {
        withMultipleValidJwksCache();
        var jwksCacheItem = jwksCacheServiceSpy.getOrGenerateIpvJwksCacheItem();
        assertThat(jwksCacheItem.getKeyId(), equalTo(KEY_ID_1));
        assertThat(jwksCacheItem.getTimeToLive(), equalTo(VALID_TTL));
    }

    // QualityGateRegressionTest
    @Test
    void getOrGenerateIpvJwksCacheItemGeneratesJwksIfNone() {
        Stream<JwksCacheItem> jwksCacheItemStream = Stream.of();
        doReturn(jwksCacheItemStream).when(jwksCacheServiceSpy).queryTableStream(JWKS_URL);
        jwksUtilsMockedStatic
                .when(() -> JwksUtils.getKey(new URL(JWKS_URL), KeyUse.ENCRYPTION))
                .thenReturn(JWK_2);
        var jwksCacheItem = jwksCacheServiceSpy.getOrGenerateIpvJwksCacheItem();
        assertThat(jwksCacheItem.getKeyId(), equalTo(KEY_ID_2));
    }

    private void withValidJwksCache() {
        JwksCacheItem existingJwksCache = new JwksCacheItem(JWKS_URL, JWK_1, VALID_TTL);
        Stream<JwksCacheItem> jwksCacheItemStream = Stream.of(existingJwksCache);
        doReturn(jwksCacheItemStream).when(jwksCacheServiceSpy).queryTableStream(JWKS_URL);
    }

    private void withMultipleValidJwksCache() {
        JwksCacheItem firstExistingJwksCache = new JwksCacheItem(JWKS_URL, JWK_1, VALID_TTL);
        JwksCacheItem secondExistingJwksCache = new JwksCacheItem(JWKS_URL, JWK_2, VALID_TTL);
        Stream<JwksCacheItem> jwksCacheItemStream =
                Stream.of(firstExistingJwksCache, secondExistingJwksCache);
        doReturn(jwksCacheItemStream).when(jwksCacheServiceSpy).queryTableStream(JWKS_URL);
    }

    public static JWK createPublicJwk(String keyId) {
        var keyPair = generateRsaKeyPair();
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.RSA_OAEP_256)
                .keyID(keyId)
                .build();
    }
}
