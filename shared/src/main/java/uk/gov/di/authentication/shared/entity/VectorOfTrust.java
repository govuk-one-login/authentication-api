package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class VectorOfTrust {

    @JsonProperty("credential_trust_level")
    private final CredentialTrustLevel credentialTrustLevel;

    @JsonCreator
    private VectorOfTrust(
            @JsonProperty(required = true, value = "credential_trust_level")
                    CredentialTrustLevel credentialTrustLevel) {
        this.credentialTrustLevel = credentialTrustLevel;
    }

    public CredentialTrustLevel getCredentialTrustLevel() {
        return credentialTrustLevel;
    }

    public static VectorOfTrust parse(List<String> vtr, VectorOfTrust clientDefaults) {
        if (Objects.isNull(vtr)) {
            return clientDefaults;
        }
        return parse(String.join(".", vtr), clientDefaults.getCredentialTrustLevel());
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

    public static VectorOfTrust getDefaults() {
        return new VectorOfTrust(CredentialTrustLevel.getDefault());
    }
}
