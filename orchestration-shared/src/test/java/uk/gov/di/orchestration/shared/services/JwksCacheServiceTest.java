package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;

import java.time.Instant;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class JwksCacheServiceTest {
    private static final String JWKS_URL = "test-session-id";
    private static final String KEY_ID_1 = "test-enc-key-1";
    private static final String KEY_ID_2 = "test-enc-key-2";
    private static final long VALID_TTL = Instant.now().plusSeconds(100).getEpochSecond();
    private static final long EXPIRED_TTL = Instant.now().minusSeconds(100).getEpochSecond();
    private final DynamoDbTable<JwksCacheItem> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private JwksCacheService jwksCacheServiceSpy;

    @BeforeEach
    void setup() {
        JwksCacheService jwksCacheService =
                new JwksCacheService(dynamoDbClient, table, configurationService);
        jwksCacheServiceSpy = Mockito.spy(jwksCacheService);
    }

    @Test
    void getEncryptionKeyReturnsJwksCacheWithValidTtl() {
        withValidJwksCache();
        var jwksCacheItem = jwksCacheServiceSpy.getEncryptionKey(JWKS_URL);
        assertThat(jwksCacheItem.isPresent(), equalTo(true));
    }

    @Test
    void getEncryptionKeyReturnsFirstJwksCache() {
        withMultipleValidJwksCache();
        var jwksCacheItem = jwksCacheServiceSpy.getEncryptionKey(JWKS_URL);
        assertThat(jwksCacheItem.isPresent(), equalTo(true));
        assertThat(jwksCacheItem.get().getKeyId(), equalTo(KEY_ID_1));
    }

    @Test
    void getEncryptionKeyReturnsEmptyOptionalWhenExpired() {
        withExpiredJwksCache();
        var jwksCacheItem = jwksCacheServiceSpy.getEncryptionKey(JWKS_URL);
        assertThat(jwksCacheItem.isPresent(), equalTo(false));
    }

    private void withValidJwksCache() {
        JwksCacheItem existingJwksCache = new JwksCacheItem(JWKS_URL, KEY_ID_1, VALID_TTL);
        Stream<JwksCacheItem> jwksCacheItemStream = Stream.of(existingJwksCache);
        doReturn(jwksCacheItemStream).when(jwksCacheServiceSpy).queryTableStream(JWKS_URL);
    }

    private void withMultipleValidJwksCache() {
        JwksCacheItem firstExistingJwksCache = new JwksCacheItem(JWKS_URL, KEY_ID_1, VALID_TTL);
        JwksCacheItem secondExistingJwksCache = new JwksCacheItem(JWKS_URL, KEY_ID_2, VALID_TTL);
        Stream<JwksCacheItem> jwksCacheItemStream =
                Stream.of(firstExistingJwksCache, secondExistingJwksCache);
        doReturn(jwksCacheItemStream).when(jwksCacheServiceSpy).queryTableStream(JWKS_URL);
    }

    private void withExpiredJwksCache() {
        Stream<JwksCacheItem> jwksCacheItemStream =
                Stream.of(new JwksCacheItem(JWKS_URL, KEY_ID_1, EXPIRED_TTL));
        doReturn(jwksCacheItemStream).when(jwksCacheServiceSpy).queryTableStream(JWKS_URL);
    }
}
