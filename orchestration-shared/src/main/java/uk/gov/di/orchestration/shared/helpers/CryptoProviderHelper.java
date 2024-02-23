package uk.gov.di.orchestration.shared.helpers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;

import static java.util.Objects.isNull;

public class CryptoProviderHelper {

    private static Provider INSTANCE;

    public static Provider bouncyCastle() {
        if (INSTANCE.isNull()) {
            INSTANCE = new BouncyCastleProvider();
        }
        return INSTANCE;
    }
}
