package uk.gov.di.authentication.shared.helpers;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.util.Arrays;
import java.util.List;

public class EnvironmentAwareCryptoProvider {

    private static final List<String> ENABLED_ENVIRONMENTS = Arrays.asList("CI", "build");

    static {
        if (ENABLED_ENVIRONMENTS.contains(System.getenv("ENVIRONMENT"))) {
            AmazonCorrettoCryptoProvider.install();
        }
    }

    public static Provider provider() {
        if (AmazonCorrettoCryptoProvider.INSTANCE.getLoadingError() != null) {
            System.out.println(
                    AmazonCorrettoCryptoProvider.INSTANCE.getLoadingError().getMessage());
        }

        if (ENABLED_ENVIRONMENTS.contains(System.getenv("ENVIRONMENT"))) {
            return new AmazonCorrettoCryptoProvider();
        } else {
            return new BouncyCastleProvider();
        }
    }
}
