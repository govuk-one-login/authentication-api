package uk.gov.di.authentication.shared.helpers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;

import static java.util.Objects.isNull;

public class CryptoProviderHelper {

    private static Provider INSTANCE;

    public static Provider bouncyCastle() {
        if (isNull(INSTANCE)) {
            INSTANCE = new BouncyCastleProvider();
        }
        return INSTANCE;
    }
}
