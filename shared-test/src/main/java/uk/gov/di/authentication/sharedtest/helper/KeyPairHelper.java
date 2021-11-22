package uk.gov.di.authentication.sharedtest.helper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static java.util.Objects.isNull;

public class KeyPairHelper {

    private KeyPairHelper() {}

    private static KeyPair cachedKeyPair = null;

    public static final KeyPair GENERATE_RSA_KEY_PAIR() {
        if (isNull(KeyPairHelper.cachedKeyPair)) {
            KeyPairGenerator kpg;
            try {
                kpg = KeyPairGenerator.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException();
            }
            kpg.initialize(2048);
            KeyPairHelper.cachedKeyPair = kpg.generateKeyPair();
        }
        return KeyPairHelper.cachedKeyPair;
    }
}
