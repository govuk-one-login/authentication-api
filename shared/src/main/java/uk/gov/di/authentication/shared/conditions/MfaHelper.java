package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;

import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;

public class MfaHelper {

    private MfaHelper() {}

    public static boolean mfaRequired(Map<String, List<String>> authRequestParams) {
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(authRequestParams);
        } catch (ParseException e) {
            throw new RuntimeException();
        }
        List<String> vtr = authRequest.getCustomParameter("vtr");
        VectorOfTrust vectorOfTrust = VectorOfTrust.parseFromAuthRequestAttribute(vtr);

        return !vectorOfTrust.getCredentialTrustLevel().equals(LOW_LEVEL);
    }
}
