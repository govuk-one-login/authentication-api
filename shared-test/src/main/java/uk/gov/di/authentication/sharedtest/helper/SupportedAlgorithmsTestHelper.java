package uk.gov.di.authentication.sharedtest.helper;

import com.nimbusds.jose.JWSAlgorithm;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Map;

public class SupportedAlgorithmsTestHelper {
    private SupportedAlgorithmsTestHelper() {}

    private static final Map<JWSAlgorithm, AlgorithmParameterSpec> algorithmKeySpec =
            Map.ofEntries(
                    Map.entry(
                            JWSAlgorithm.RS256,
                            new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)),
                    Map.entry(
                            JWSAlgorithm.RS384,
                            new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)),
                    Map.entry(
                            JWSAlgorithm.RS512,
                            new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)),
                    Map.entry(
                            JWSAlgorithm.PS256,
                            new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)),
                    Map.entry(
                            JWSAlgorithm.PS384,
                            new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)),
                    Map.entry(
                            JWSAlgorithm.PS512,
                            new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)),
                    Map.entry(JWSAlgorithm.ES256, new ECGenParameterSpec("secp256r1")),
                    Map.entry(JWSAlgorithm.ES384, new ECGenParameterSpec("secp384r1")),
                    Map.entry(JWSAlgorithm.ES512, new ECGenParameterSpec("secp521r1")));

    public static String getAlgorithmFamilyName(JWSAlgorithm algorithmName) {
        return algorithmKeySpec.get(algorithmName) instanceof ECGenParameterSpec ? "EC" : "RSA";
    }

    public static AlgorithmParameterSpec getKeyGenParameterSpec(JWSAlgorithm algorithmName) {
        return algorithmKeySpec.get(algorithmName);
    }
}
