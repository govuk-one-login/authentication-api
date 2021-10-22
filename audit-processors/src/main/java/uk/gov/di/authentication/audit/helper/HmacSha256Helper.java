package uk.gov.di.authentication.audit.helper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HmacSha256Helper {

    public static byte[] hmacSha256(String input, String secret) {
        try {
            var hmac = Mac.getInstance("HmacSHA256");

            hmac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));

            return hmac.doFinal(input.getBytes());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}
