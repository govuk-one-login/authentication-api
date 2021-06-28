package uk.gov.di.services;

import uk.gov.di.helpers.HashHelper;

import java.util.Optional;

public class CodeStorageService {

    private final RedisConnectionService redisConnectionService;
    private static final String EMAIL_KEY_PREFIX = "email-code:";

    public CodeStorageService(RedisConnectionService redisConnectionService) {
        this.redisConnectionService = redisConnectionService;
    }

    public void saveEmailCode(String email, String code, long codeExpiryTime) {
        String encodedhash = HashHelper.hashSha256String(email);
        String key = EMAIL_KEY_PREFIX + encodedhash;
        try (RedisConnectionService redis = redisConnectionService) {
            redis.saveWithExpiry(key, code, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<String> getCodeForEmail(String emailAddress) {
        return Optional.ofNullable(
                redisConnectionService.getValue(
                        EMAIL_KEY_PREFIX + HashHelper.hashSha256String(emailAddress)));
    }
}
