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
        VectorOfTrust vectorOfTrust = VectorOfTrust.parseFromAuthRequestAttribute(vtr);
        return Objects.nonNull(vectorOfTrust.getLevelOfConfidence())
                && !(vectorOfTrust.getLevelOfConfidence().equals(NONE));
    }
}
