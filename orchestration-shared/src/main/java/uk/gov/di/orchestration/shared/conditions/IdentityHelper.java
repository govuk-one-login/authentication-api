package uk.gov.di.orchestration.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrList;

import java.util.List;
import java.util.Map;

public class IdentityHelper {

    private IdentityHelper() {}

    public static boolean identityRequired(
            Map<String, List<String>> authRequestParams,
            boolean clientSupportsIdentityVerification,
            boolean identityEnabled) {
        if (!clientSupportsIdentityVerification || !identityEnabled) {
            return false;
        }
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(authRequestParams);
        } catch (ParseException e) {
            throw new RuntimeException();
        }
        List<String> vtr = authRequest.getCustomParameter("vtr");
        var vtrList = VtrList.parseFromAuthRequestAttribute(vtr);
        return vtrList.identityRequired();
    }
}
