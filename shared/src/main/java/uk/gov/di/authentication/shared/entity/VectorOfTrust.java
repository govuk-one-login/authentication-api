package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;
import java.util.List;

public class VectorOfTrust {

    private final CredentialTrustLevel credentialTrustLevel;

    private VectorOfTrust(CredentialTrustLevel credentialTrustLevel) {
        this.credentialTrustLevel = credentialTrustLevel;
    }

    public CredentialTrustLevel getCredentialTrustLevel() {
        return credentialTrustLevel;
    }

    public static final VectorOfTrust parse(List<String> vtr) {
        return parse(String.join(".", vtr), null);
    }

    public static final VectorOfTrust parse(
            String vtr, CredentialTrustLevel defaultCredentialsTrustLevel) {
        List<String> vectors = Arrays.asList(vtr.split("\\."));
        CredentialTrustLevel credentialTrustLevel = defaultCredentialsTrustLevel;
        for (String vector : vectors) {
            if (vector.startsWith(("C"))) {
                credentialTrustLevel = CredentialTrustLevel.parseByValue(vector);
            }
        }
        return new VectorOfTrust(credentialTrustLevel);
    }
}
