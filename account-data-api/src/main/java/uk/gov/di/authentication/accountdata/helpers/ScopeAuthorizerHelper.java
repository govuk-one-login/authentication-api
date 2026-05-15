package uk.gov.di.authentication.accountdata.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.AccountDataScope;

public class ScopeAuthorizerHelper {
    private static final Logger LOG = LogManager.getLogger(ScopeAuthorizerHelper.class);
    private static final String SCOPE_FIELD = "scope";

    private ScopeAuthorizerHelper() {}

    public static boolean isScopeAuthorized(
            AccountDataScope expectedScope,
            APIGatewayProxyRequestEvent.ProxyRequestContext requestContext) {
        if (requestContext.getAuthorizer() == null
                || !requestContext.getAuthorizer().containsKey(SCOPE_FIELD)) {
            LOG.warn("Authorizer missing from request context or scope not present");
            return false;
        }
        var scope = requestContext.getAuthorizer().get(SCOPE_FIELD).toString();
        var matches = expectedScope.getValue().equals(scope);
        if (!matches) {
            LOG.warn("Scope {} does not match expected scope {}", scope, expectedScope.getValue());
        }
        return matches;
    }
}
