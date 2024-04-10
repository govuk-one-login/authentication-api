package uk.gov.di.orchestration.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.NONE;

public class IdentityHelper {

    private IdentityHelper() {}

    public static boolean identityRequired(
            Map<String, List<String>> authRequestParams,
            boolean clientSupportsIdentityVerification) {
        if (!clientSupportsIdentityVerification) {
            return false;
        }
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(authRequestParams);
        } catch (ParseException e) {
            throw new RuntimeException();
        }
        List<String> vtr = authRequest.getCustomParameter("vtr");
        List<VectorOfTrust> vtrList = VectorOfTrust.parseFromAuthRequestAttribute(vtr);
        // Assumption: Requested vectors of trust will either all be for identity or none, and so we
        // can check just the first
        return Objects.nonNull(vtrList.get(0).getLevelOfConfidence())
                && !(vtrList.get(0).getLevelOfConfidence().equals(NONE));
    }
}
