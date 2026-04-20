package uk.gov.di.authentication.accountdata.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SubjectIdAuthorizerHelper {
    private static final Logger LOG = LogManager.getLogger(SubjectIdAuthorizerHelper.class);

    private SubjectIdAuthorizerHelper() {
        /* This utility class should not be instantiated */
    }

    private static final String PRINCIPAL_ID_FIELD = "principalId";

    public static boolean isSubjectIdAuthorized(
            String publicSubjectId,
            APIGatewayProxyRequestEvent.ProxyRequestContext requestContext) {
        if (requestContext.getAuthorizer() == null
                || !requestContext.getAuthorizer().containsKey(PRINCIPAL_ID_FIELD)) {
            LOG.warn("Authorizer missing from request context or principalId not present");
            return false;
        }
        var principalId = requestContext.getAuthorizer().get(PRINCIPAL_ID_FIELD).toString();
        var matches = principalId.equals(publicSubjectId);
        if (!matches) {
            LOG.warn(
                    "PrincipalId in authorizer {} does not match publicSubjectId in path {}",
                    principalId,
                    publicSubjectId);
        } else {
            LOG.info("PrincipalId matches publicSubjectId");
        }
        return matches;
    }
}
