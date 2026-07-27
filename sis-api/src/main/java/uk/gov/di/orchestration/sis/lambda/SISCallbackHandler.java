package uk.gov.di.orchestration.sis.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.CrossBrowserNoSessionException;
import uk.gov.di.orchestration.identity.entity.CrossBrowserStateMismatchException;
import uk.gov.di.orchestration.identity.entity.IdentityContext;
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.identity.helpers.IdentityCallbackHelper;
import uk.gov.di.orchestration.identity.service.IdentityContextService;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.EndOfJourneyService;

import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED;

public class SISCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(SISCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final IdentityCallbackHelper identityCallbackHelper;
    private final IdentityContextService identityContextService;
    private final AuditService auditService;
    private final EndOfJourneyService endOfJourneyService;

    public SISCallbackHandler(
            ConfigurationService configurationService,
            IdentityCallbackHelper identityCallbackHelper,
            IdentityContextService identityContextService,
            AuditService auditService,
            EndOfJourneyService endOfJourneyService) {
        this.configurationService = configurationService;
        this.identityCallbackHelper = identityCallbackHelper;
        this.identityContextService = identityContextService;
        this.auditService = auditService;
        this.endOfJourneyService = endOfJourneyService;
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
            var identityContextResponse = getIdentityContext(input);
            if (identityContextResponse.earlyRedirect != null) {
                return identityContextResponse.earlyRedirect;
            }
        } catch (IdentityCallbackException e) {
            return identityCallbackHelper.redirectToFrontendErrorPageWithErrorLog(e);
        } catch (NoSessionException e) {
            return identityCallbackHelper.redirectToFrontendErrorPageForNoSession(e);
        } catch (ParseException e) {
            return identityCallbackHelper.redirectToFrontendErrorPageWithErrorLog(
                    new Error("Cannot retrieve auth request params from client session id"));
        }
        return null;
    }

    private IdentityContextResponse getIdentityContext(APIGatewayProxyRequestEvent input)
            throws ParseException, NoSessionException, IdentityCallbackException {
        try {
            return new IdentityContextResponse(identityContextService.buildContext(input), null);
        } catch (CrossBrowserStateMismatchException | CrossBrowserNoSessionException e) {
            var authRequest =
                    AuthenticationRequest.parse(
                            e.getEntity().getClientSession().getAuthRequestParams());
            attachLogFieldToLogs(CLIENT_ID, authRequest.getClientID().getValue());
            auditService.submitAuditEvent(
                    ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                    authRequest.getClientID().getValue(),
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(e.getEntity().getClientSessionId())
                            .withSessionId(AuditService.UNKNOWN));

            var additionalLog =
                    "No Session Error: " + (e instanceof CrossBrowserNoSessionException);
            return new IdentityContextResponse(
                    null,
                    endOfJourneyService.generateAuthenticationErrorResponse(
                            authRequest, e.getEntity().getErrorObject(), additionalLog));
        }
    }

    private record IdentityContextResponse(
            IdentityContext identityContext, APIGatewayProxyResponseEvent earlyRedirect) {}
}
