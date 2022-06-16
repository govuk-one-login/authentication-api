package uk.gov.di.authentication.shared.configuration;

import java.util.Map;

import static java.text.MessageFormat.format;

public class RedisConfiguration extends SsmAwareConfiguration {

    private static final String ENVIRONMENT = System.getenv().getOrDefault("ENVIRONMENT", "test");
    private static final String REDIS_KEY = System.getenv("REDIS_KEY");

    private static final Map<String, String> REDIS_SSM_PARAMETERS =
            getParameters(
                    format("{0}-{1}-redis-master-host", ENVIRONMENT, REDIS_KEY),
                    format("{0}-{1}-redis-password", ENVIRONMENT, REDIS_KEY),
                    format("{0}-{1}-redis-port", ENVIRONMENT, REDIS_KEY),
                    format("{0}-{1}-redis-tls", ENVIRONMENT, REDIS_KEY));

    public Map<String, String> getSsmRedisParameters() {
        return REDIS_SSM_PARAMETERS;
    }
}
