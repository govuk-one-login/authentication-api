package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Objects;

import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.retrieveCredentialTrustLevel;

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

    public static final VectorOfTrust parse(List<String> vtr) {
        if (Objects.isNull(vtr) || vtr.isEmpty()) {
            return new VectorOfTrust(CredentialTrustLevel.getDefault());
        }
        return new VectorOfTrust(retrieveCredentialTrustLevel(vtr));
    }

    public static VectorOfTrust getDefaults() {
        return new VectorOfTrust(CredentialTrustLevel.getDefault());
    }
}
