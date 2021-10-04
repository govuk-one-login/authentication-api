package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;
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

    public static final VectorOfTrust parseFromAuthRequestAttribute(List<String> vtr) {
        if (Objects.isNull(vtr) || vtr.isEmpty()) {
            return new VectorOfTrust(CredentialTrustLevel.getDefault());
        }
        JSONParser parser = new JSONParser(DEFAULT_PERMISSIVE_MODE);
        JSONArray vtrJsonArray;
        try {
            vtrJsonArray = (JSONArray) parser.parse(vtr.get(0));
        } catch (net.minidev.json.parser.ParseException | ClassCastException e) {
            throw new IllegalArgumentException("Invalid VTR attribute", e);
        }
        List<String> vtrSets = new ArrayList<>();
        for (int i = 0; i < vtrJsonArray.size(); i++) {
            vtrSets.add((String) vtrJsonArray.get(i));
        }
        return new VectorOfTrust(retrieveCredentialTrustLevel(vtrSets));
    }

    public static VectorOfTrust getDefaults() {
        return new VectorOfTrust(CredentialTrustLevel.getDefault());
    }
}
