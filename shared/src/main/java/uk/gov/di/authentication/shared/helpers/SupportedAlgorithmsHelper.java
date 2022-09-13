package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.jose.JWSAlgorithm;

import java.util.Map;

public class SupportedAlgorithmsHelper {
    private static final Map<JWSAlgorithm, String> algorithmKeySpec =
            Map.ofEntries(
                    Map.entry(JWSAlgorithm.RS256, "RSA"),
                    Map.entry(JWSAlgorithm.RS384, "RSA"),
                    Map.entry(JWSAlgorithm.RS512, "RSA"),
                    Map.entry(JWSAlgorithm.PS256, "RSA"),
                    Map.entry(JWSAlgorithm.PS384, "RSA"),
                    Map.entry(JWSAlgorithm.PS512, "RSA"),
                    Map.entry(JWSAlgorithm.ES256, "EC"),
                    Map.entry(JWSAlgorithm.ES384, "EC"),
                    Map.entry(JWSAlgorithm.ES512, "EC"));

    public static String getAlgorithmFamilyName(JWSAlgorithm algorithmName) {
        return algorithmKeySpec.get(algorithmName);
    }
}
