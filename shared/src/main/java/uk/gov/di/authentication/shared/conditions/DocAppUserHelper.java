package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.state.UserContext;

public class DocAppUserHelper {

    private DocAppUserHelper() {}

    public static boolean isDocCheckingAppUser(UserContext context) {
        var authRequestParams = context.getClientSession().getAuthRequestParams();
        if (Boolean.FALSE.equals(authRequestParams.containsKey("request"))) {
            return false;
        }
        try {
            var authRequest = AuthenticationRequest.parse(authRequestParams);
            var requestObject = authRequest.getRequestObject();
            var claimScope = (String) requestObject.getJWTClaimsSet().getClaim("scope");
            var scope = Scope.parse(claimScope);
            if (Boolean.FALSE.equals(scope.contains(CustomScopeValue.DOC_CHECKING_APP))) {
                return false;
            }
            return context.getClient()
                    .filter(t -> t.getClientType().equals(ClientType.APP.getValue()))
                    .isPresent();
        } catch (ParseException | java.text.ParseException e) {
            throw new RuntimeException();
        }
    }
}
