package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

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

    public static final VectorOfTrust parse(String vtr) {
        return parse(vtr, null);
    }

    public static final VectorOfTrust parse(
            String vtr, CredentialTrustLevel defaultCredentialsTrustLevel) {
        CredentialTrustLevel credentialTrustLevel = defaultCredentialsTrustLevel;
        if (Objects.nonNull(vtr)) {
            List<String> vectors = Arrays.asList(vtr.split("\\."));
            for (String vector : vectors) {
                if (vector.startsWith(("C"))) {
                    credentialTrustLevel = CredentialTrustLevel.parseByValue(vector);
                }
            }
        }
        return new VectorOfTrust(credentialTrustLevel);
    }
}
