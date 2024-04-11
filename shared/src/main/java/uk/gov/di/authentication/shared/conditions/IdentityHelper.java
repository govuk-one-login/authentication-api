package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;

public class IdentityHelper {

    private IdentityHelper() {}

    public static boolean identityRequired(
            Boolean identityRequired,
            Map<String, List<String>> authRequestParams,
            boolean clientSupportsIdentityVerification,
            boolean identityEnabled) {
        // ATO-98: This should only ever be null if a session was in progress during release.
        boolean isIdentityRequired =
                identityRequired != null
                        ? identityRequired
                        : extractIdentityRequired(authRequestParams);
        return clientSupportsIdentityVerification && identityEnabled && isIdentityRequired;
    }

    private static boolean extractIdentityRequired(Map<String, List<String>> authRequestParams) {
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(authRequestParams);
        } catch (ParseException e) {
            throw new RuntimeException();
        }
        List<String> vtr = authRequest.getCustomParameter("vtr");
        VectorOfTrust vectorOfTrust = VectorOfTrust.parseFromAuthRequestAttribute(vtr);
        return Objects.nonNull(vectorOfTrust.getLevelOfConfidence())
                && !(vectorOfTrust.getLevelOfConfidence().equals(NONE));
    }
}
