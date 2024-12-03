package uk.gov.di.orchestration.shared.helpers;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

public class SaltHelper {

    private static final int SALT_BYTES = 32;
    private static final SecureRandom secureRandom = new SecureRandom();

    private SaltHelper() {}

    public static byte[] generateNewSalt() {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] convertToByteArrayAndRewindBuffer(ByteBuffer byteBuffer) {
        byte[] byteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(byteArray);
        byteBuffer.rewind();
        return byteArray;
    }

    public static String byteBufferToBase64(ByteBuffer byteBuffer) {
        byte[] byteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(byteArray);
        return Base64.getEncoder().encodeToString(byteArray);
    }

    public static byte[] base64ToBytes(String saltAsBase64String) {
        return Base64.getDecoder().decode(saltAsBase64String);
    }
}
