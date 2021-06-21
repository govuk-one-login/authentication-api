package uk.gov.di.helpers;

import java.security.SecureRandom;
import java.util.Base64;

public class IdGenerator {
    private static final int ENTROPY_BYTES = 20;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    public static String generate() {
        byte[] buffer = new byte[ENTROPY_BYTES];
        RANDOM.nextBytes(buffer);
        return ENCODER.encodeToString(buffer);
    }
}
