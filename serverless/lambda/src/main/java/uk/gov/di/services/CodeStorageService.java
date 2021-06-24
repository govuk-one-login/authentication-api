package uk.gov.di.services;

import uk.gov.di.helpers.HashHelper;

public class CodeStorageService {

    private final RedisConnectionService redisConnectionService;
    private static final String EMAIL_KEY_PREFIX = "email-code:";
    private static final long CODE_EXPIRY_TIME = 900l;

    public CodeStorageService(RedisConnectionService redisConnectionService) {
        this.redisConnectionService = redisConnectionService;
    }

    public void saveEmailCode(String email, String code) {
        String encodedhash = HashHelper.hashSha256String(email);
        String key = EMAIL_KEY_PREFIX + encodedhash;
        try (RedisConnectionService redis = redisConnectionService) {
            redis.saveCodeWithExpiry(key, code, CODE_EXPIRY_TIME);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
