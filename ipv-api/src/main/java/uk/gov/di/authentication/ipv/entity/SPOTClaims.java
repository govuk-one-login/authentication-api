package uk.gov.di.authentication.ipv.entity;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.authentication.shared.entity.IdentityClaims.SUB;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.VTM;

public class SPOTClaims {

    private SPOTClaims() {}

    public static SPOTClaimsBuilder builder() {
        return new SPOTClaimsBuilder();
    }

    public static class SPOTClaimsBuilder {
        Map<String, Object> spotClaims = new HashMap<>();

        public SPOTClaimsBuilder withClaims(HashMap<String, Object> claims) {
            claims.entrySet().stream()
                    .filter(SPOTClaimsBuilder::isAddableClaim)
                    .forEach(c -> spotClaims.put(c.getKey(), c.getValue()));
            return this;
        }

        private static boolean isAddableClaim(Map.Entry claim) {
            return !claim.getKey().equals(SUB.getValue()) && !claim.getKey().equals(VTM.getValue());
        }

        public SPOTClaimsBuilder withVot(Object vot) {
            return withClaim(VOT.getValue(), vot);
        }

        public SPOTClaimsBuilder withVtm(Object vtm) {
            return withClaim(VTM.getValue(), vtm);
        }

        public SPOTClaimsBuilder withClaim(String claimName, Object claimValue) {
            spotClaims.put(claimName, claimValue);
            return this;
        }

        public SPOTClaimsBuilder withClaimArray(String claimName, Object claimValues) {
            spotClaims.put(claimName, claimValues);
            return this;
        }

        public Map<String, Object> build() {
            return Collections.unmodifiableMap(spotClaims);
        }
    }
}
