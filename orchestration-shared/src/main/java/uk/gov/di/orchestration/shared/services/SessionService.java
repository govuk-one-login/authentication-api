package uk.gov.di.orchestration.shared.services;

import uk.gov.di.orchestration.shared.serialization.Json;

public class SessionService {

    private static final Json OBJECT_MAPPER = SerializationService.getInstance();

    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;

    public SessionService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
    }

    public SessionService(ConfigurationService configurationService) {
        this(
                configurationService,
                new RedisConnectionService(
                        configurationService.getRedisHost(),
                        configurationService.getRedisPort(),
                        configurationService.getUseRedisTLS(),
                        configurationService.getRedisPassword()));
    }
}
