package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.UUID;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.nullValue;

class RedisConnectionServiceIntegrationTest {
    private static final String REDIS_HOST =
            System.getenv().getOrDefault("REDIS_HOST", "localhost");
    private static final Optional<String> REDIS_PASSWORD =
            Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
    private static final int REDIS_PORT = 6379;
    private static final String TEST_VALUE = "my-test-value";
    public static final int TEN_SECOND_EXPIRY = 60000;

    private String testKey = "int-test-key-" + UUID.randomUUID();
    private static final RedisConfigurationService REDIS_CONFIGURATION_SERVICE =
            new RedisConfigurationService();

    @Test
    void shouldSuccessfullySaveAndRetrieveIfRedisAvailable() {
        var redis = RedisConnectionService.getInstance(REDIS_CONFIGURATION_SERVICE);

        redis.saveWithExpiry(testKey, TEST_VALUE, TEN_SECOND_EXPIRY);

        assertThat(redis.getValue(testKey), equalTo(TEST_VALUE));
    }

    @Test
    void shouldSuccessfullyCreateAValueThatExpires() {
        var redis = RedisConnectionService.getInstance(REDIS_CONFIGURATION_SERVICE);
        redis.saveWithExpiry(testKey, TEST_VALUE, 1);

        await().atMost(2, SECONDS)
                .untilAsserted(() -> assertThat(redis.getValue(testKey), is(nullValue())));
    }

    @Test
    void keyExistsShouldCorrectlyReturnTrueWhenKeyExists() {
        var redis = RedisConnectionService.getInstance(REDIS_CONFIGURATION_SERVICE);
        redis.saveWithExpiry(testKey, TEST_VALUE, TEN_SECOND_EXPIRY);

        assertThat(redis.keyExists(testKey), is(true));
    }

    @Test
    void keyExistsShouldCorrectlyReturnFalseWhenKeyExists() {
        var redis = RedisConnectionService.getInstance(REDIS_CONFIGURATION_SERVICE);

        assertThat(redis.keyExists(testKey), is(false));
    }

    @Test
    void popValueShouldReturnValueAndClearKeyWhenItExists() {
        var redis = RedisConnectionService.getInstance(REDIS_CONFIGURATION_SERVICE);
        redis.saveWithExpiry(testKey, TEST_VALUE, TEN_SECOND_EXPIRY);

        assertThat(redis.popValue(testKey), equalTo(TEST_VALUE));
        assertThat(redis.keyExists(testKey), is(false));
    }

    @Test
    void getValueReturnsNullIfKeyDoesNotExist() {
        var redis = RedisConnectionService.getInstance(REDIS_CONFIGURATION_SERVICE);
        assertThat(redis.getValue(testKey), is(nullValue()));
    }

    @Test
    void deleteValueRemovesValueFromRedisIfExists() {
        var redis = RedisConnectionService.getInstance(REDIS_CONFIGURATION_SERVICE);
        redis.saveWithExpiry(testKey, TEST_VALUE, TEN_SECOND_EXPIRY);
        redis.deleteValue(testKey);
        assertThat(redis.keyExists(testKey), is(false));
    }

    @Test
    void deleteValueDoesNotErrorIfKeyDoesNotExist() {
        var redis = RedisConnectionService.getInstance(REDIS_CONFIGURATION_SERVICE);
        redis.deleteValue(testKey);
        assertThat(redis.keyExists(testKey), is(false));
    }

    private static class RedisConfigurationService extends ConfigurationService {
        @Override
        public String getRedisHost() {
            return REDIS_HOST;
        }

        @Override
        public Optional<String> getRedisPassword() {
            return REDIS_PASSWORD;
        }

        @Override
        public int getRedisPort() {
            return REDIS_PORT;
        }

        @Override
        public boolean getUseRedisTLS() {
            return false;
        }
    }
}
