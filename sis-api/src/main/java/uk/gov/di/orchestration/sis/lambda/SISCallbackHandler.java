package uk.gov.di.orchestration.sis.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.identity.helpers.IdentityCallbackHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;

public class SISCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(SISCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final IdentityCallbackHelper identityCallbackHelper;

    public SISCallbackHandler(
            ConfigurationService configurationService,
            IdentityCallbackHelper identityCallbackHelper) {
        this.configurationService = configurationService;
        this.identityCallbackHelper = identityCallbackHelper;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        ThreadContext.clearMap();
        attachTraceId();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        LOG.info("Request received to SISCallbackHandler");
        attachTxmaAuditFieldFromHeaders(input.getHeaders());
        try {
            if (!configurationService.isIdentityEnabled()) {
                throw new IdentityCallbackException("Identity is not enabled");
            }
        } catch (IdentityCallbackException e) {
            return identityCallbackHelper.redirectToFrontendErrorPageWithErrorLog(e);
        }
        return null;
    }
}
