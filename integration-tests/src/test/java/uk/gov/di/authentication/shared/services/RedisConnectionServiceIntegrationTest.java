package uk.gov.di.authentication.shared.services;

import io.lettuce.core.RedisURI;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RedisConnectionServiceIntegrationTest {
    private static final String REDIS_HOST =
            System.getenv().getOrDefault("REDIS_HOST", "localhost");
    private static final Optional<String> REDIS_PASSWORD =
            Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
    private static final String TEST_VALUE = "my-test-value";
    public static final int TEN_SECOND_EXPIRY = 60000;

    private String testKey = "int-test-key-" + UUID.randomUUID();

    private static List<RedisURI> NODES;

    @BeforeAll
    static void setupRedisNodes() {
        var builder = RedisURI.builder().withHost(REDIS_HOST).withPort(6379).withSsl(false);
        REDIS_PASSWORD.ifPresent(s -> builder.withPassword(s.toCharArray()));
        NODES = List.of(builder.build());
    }

    @Test
    void shouldSuccessfullySaveAndRetrieveIfRedisAvailable() {
        try (RedisConnectionService redis = new RedisConnectionService(NODES, false)) {
            redis.saveWithExpiry(testKey, TEST_VALUE, TEN_SECOND_EXPIRY);

            assertThat(redis.getValue(testKey), equalTo(TEST_VALUE));
        }
    }

    @Test
    void shouldSuccessfullyCreateAValueThatExpires() {
        try (RedisConnectionService redis = new RedisConnectionService(NODES, false)) {
            redis.saveWithExpiry(testKey, TEST_VALUE, 1);
            await().atMost(2, SECONDS)
                    .untilAsserted(() -> assertThat(redis.getValue(testKey), is(nullValue())));
        }
    }

    @Test
    void keyExistsShouldCorrectlyReturnTrueWhenKeyExists() {
        try (RedisConnectionService redis = new RedisConnectionService(NODES, false)) {
            redis.saveWithExpiry(testKey, TEST_VALUE, TEN_SECOND_EXPIRY);

            assertThat(redis.keyExists(testKey), is(true));
        }
    }

    @Test
    void keyExistsShouldCorrectlyReturnFalseWhenKeyExists() {
        try (RedisConnectionService redis = new RedisConnectionService(NODES, false)) {
            assertThat(redis.keyExists(testKey), is(false));
        }
    }

    @Test
    void popValueShouldReturnValueAndClearKeyWhenItExists() {
        try (RedisConnectionService redis = new RedisConnectionService(NODES, false)) {
            redis.saveWithExpiry(testKey, TEST_VALUE, TEN_SECOND_EXPIRY);

            assertThat(redis.popValue(testKey), equalTo(TEST_VALUE));
            assertThat(redis.keyExists(testKey), is(false));
        }
    }

    @Test
    void getValueReturnsNullIfKeyDoesNotExist() {
        try (RedisConnectionService redis = new RedisConnectionService(NODES, false)) {
            assertThat(redis.getValue(testKey), is(nullValue()));
        }
    }

    @Test
    void deleteValueRemovesValueFromRedisIfExists() {
        try (RedisConnectionService redis = new RedisConnectionService(NODES, false)) {
            redis.saveWithExpiry(testKey, TEST_VALUE, TEN_SECOND_EXPIRY);
            redis.deleteValue(testKey);
            assertThat(redis.keyExists(testKey), is(false));
        }
    }

    @Test
    void deleteValueDoesNotErrorIfKeyDoesNotExist() {
        try (RedisConnectionService redis = new RedisConnectionService(NODES, false)) {
            redis.deleteValue(testKey);
            assertThat(redis.keyExists(testKey), is(false));
        }
    }

    @Test
    void shouldThrowRedisConnectionExceptionIfRedisUnavailable() {
        var builder = RedisURI.builder().withHost("bad-host-name").withPort(6379).withSsl(false);
        try (RedisConnectionService redis =
                new RedisConnectionService(List.of(builder.build()), false)) {
            assertThrows(
                    RedisConnectionService.RedisConnectionException.class,
                    () -> redis.saveWithExpiry(testKey, TEST_VALUE, TEN_SECOND_EXPIRY));
        }
    }
}
