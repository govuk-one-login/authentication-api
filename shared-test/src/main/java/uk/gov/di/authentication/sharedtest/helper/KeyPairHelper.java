package uk.gov.di.authentication.sharedtest.helper;

import com.nimbusds.jose.JWSAlgorithm;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static java.util.Objects.isNull;
import static uk.gov.di.authentication.sharedtest.helper.SupportedAlgorithmsTestHelper.getAlgorithmFamilyName;
import static uk.gov.di.authentication.sharedtest.helper.SupportedAlgorithmsTestHelper.getKeyGenParameterSpec;

public class KeyPairHelper {

    private KeyPairHelper() {}

    private static KeyPair cachedKeyPair = null;

    public static KeyPair generateRsaKeyPair() {
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

    public static KeyPair generateRsaOrEcKeyPair(JWSAlgorithm algorithm) {
        KeyPairGenerator kpg;
        String algorithmFamily = getAlgorithmFamilyName(algorithm);
        try {
            kpg = KeyPairGenerator.getInstance(algorithmFamily);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        var keySpec = getKeyGenParameterSpec(algorithm);
        try {
            kpg.initialize(keySpec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        return kpg.generateKeyPair();
    }
}
