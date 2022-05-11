package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.exceptions.RequestObjectException;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;

import static java.lang.String.format;

public class DocAppUserHelper {

    private static final Logger LOG = LogManager.getLogger(DocAppUserHelper.class);

    private DocAppUserHelper() {}

    public static boolean isDocCheckingAppUser(UserContext context) {
        var authRequestParams = context.getClientSession().getAuthRequestParams();
        if (!authRequestParams.containsKey("request")) {
            return false;
        }
        if (!hasDocCheckingScope(authRequestParams)) {
            return false;
        } else {
            return context.getClient()
                    .filter(t -> t.getClientType().equals(ClientType.APP.getValue()))
                    .isPresent();
        }
    }

    public static boolean isDocCheckingAppUserWithSubjectId(ClientSession clientSession) {
        return clientSession.getDocAppSubjectId() != null
                && hasDocCheckingScope(clientSession.getAuthRequestParams());
    }

    private static boolean hasDocCheckingScope(Map<String, List<String>> authRequestParams) {
        try {
            var scopeClaim =
                    getRequestObjectClaim(
                            AuthenticationRequest.parse(authRequestParams), "scope", String.class);
            return (scopeClaim != null
                    && Scope.parse(scopeClaim).contains(CustomScopeValue.DOC_CHECKING_APP));
        } catch (ParseException e) {
            throw new RequestObjectException("Unable to read claim from RequestObject: scope", e);
        }
    }

    public static <T> T getRequestObjectClaim(
            AuthenticationRequest authenticationRequest, String claim, Class<T> claimType) {
        try {
            if (authenticationRequest.getRequestObject() != null
                    && authenticationRequest.getRequestObject().getJWTClaimsSet() != null
                    && authenticationRequest.getRequestObject().getJWTClaimsSet().getClaim(claim)
                            != null) {
                return claimType.cast(
                        authenticationRequest.getRequestObject().getJWTClaimsSet().getClaim(claim));
            } else {
                LOG.info("Claim is missing from RequestObject: {}", claim);
                return null;
            }
        } catch (java.text.ParseException e) {
            throw new RequestObjectException(
                    format("Unable to read claim from RequestObject: %s", claim), e);
        }
    }

    public static Scope getRequestObjectScopeClaim(AuthenticationRequest authenticationRequest) {
        try {
            if (authenticationRequest.getRequestObject() != null
                    && authenticationRequest.getRequestObject().getJWTClaimsSet() != null
                    && authenticationRequest.getRequestObject().getJWTClaimsSet().getClaim("scope")
                            != null) {
                return Scope.parse(
                        authenticationRequest
                                .getRequestObject()
                                .getJWTClaimsSet()
                                .getClaim("scope")
                                .toString());
            } else {
                LOG.info("Claim is missing from RequestObject: {}", "scope");
                throw new RuntimeException("Scope is missing from RequestObject");
            }
        } catch (java.text.ParseException e) {
            throw new RuntimeException("Unable to read scope claim from RequestObject");
        }
    }
}
