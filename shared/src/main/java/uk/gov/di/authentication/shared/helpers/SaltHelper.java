package uk.gov.di.authentication.shared.helpers;

import java.security.SecureRandom;

public class SaltHelper {

    private static final int SALT_BYTES = 32;
    private static final SecureRandom secureRandom = new SecureRandom();

    private SaltHelper() {}

    public static byte[] generateNewSalt() {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        return salt;
    }
}
