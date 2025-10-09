package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.auditevents.entity.AuthEmailFraudCheckBypassed;
import uk.gov.di.authentication.auditevents.entity.AuthEmailFraudCheckDecisionUsed;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockResponse;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Objects;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.EmailCheckResultExtractorHelper.getEmailFraudCheckResponseJsonFromResult;
import static uk.gov.di.authentication.shared.helpers.EmailCheckResultExtractorHelper.getRestrictedJsonFromResult;

public class CheckEmailFraudBlockHandler extends BaseFrontendHandler<CheckEmailFraudBlockRequest> {

    private static final Logger LOG = LogManager.getLogger(CheckEmailFraudBlockHandler.class);

    private final StructuredAuditService auditService;
    private final DynamoEmailCheckResultService dynamoEmailCheckResultService;

    protected CheckEmailFraudBlockHandler(
            ConfigurationService configurationService,
            ClientService clientService,
            AuthenticationService authenticationService,
            DynamoEmailCheckResultService dynamoEmailCheckResultService,
            StructuredAuditService auditService,
            AuthSessionService authSessionService) {
        super(
                CheckEmailFraudBlockRequest.class,
                configurationService,
                clientService,
                authenticationService,
                authSessionService);
        this.dynamoEmailCheckResultService = dynamoEmailCheckResultService;
        this.auditService = auditService;
    }

    public CheckEmailFraudBlockHandler(ConfigurationService configurationService) {
        super(CheckEmailFraudBlockRequest.class, configurationService);
        this.dynamoEmailCheckResultService =
                new DynamoEmailCheckResultService(configurationService);
        this.auditService = new StructuredAuditService(configurationService);
    }

    public CheckEmailFraudBlockHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            CheckEmailFraudBlockRequest request,
            UserContext userContext) {
        try {
            LOG.info("Request received to CheckEmailFraudBlockHandler");
            LOG.info("Checking if block is present");

            var status = EmailCheckResultStatus.PENDING;
            var emailCheckResult =
                    dynamoEmailCheckResultService.getEmailCheckStore(request.getEmail());
            if (emailCheckResult.isPresent()) {
                status = emailCheckResult.get().getStatus();
            }

            var checkEmailFraudBlockResponse = createResponse(request.getEmail(), status);

            if (status.equals(EmailCheckResultStatus.PENDING)) {
                submitEmailFraudCheckBypassedAuditEvent(input, userContext, request);
            } else {
                submitEmailFraudCheckDecisionUsedAuditEvent(
                        input, userContext, request, emailCheckResult.get());
            }

            return generateApiGatewayProxyResponse(200, checkEmailFraudBlockResponse);
        } catch (Json.JsonException e) {
            LOG.error("Unable to serialize check email fraud block response", e);
            throw new RuntimeException(e);
        }
    }

    private CheckEmailFraudBlockResponse createResponse(
            String email, EmailCheckResultStatus status) {
        return new CheckEmailFraudBlockResponse(email, status.getValue());
    }

    private void submitEmailFraudCheckBypassedAuditEvent(
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            CheckEmailFraudBlockRequest request) {
        var newAuditEvent =
                AuthEmailFraudCheckBypassed.create(
                        userContext.getAuthSession().getClientId(),
                        new AuthEmailFraudCheckBypassed.User(
                                StructuredAuditService.UNKNOWN,
                                request.getEmail(),
                                IpAddressHelper.extractIpAddress(input),
                                PersistentIdHelper.extractPersistentIdFromHeaders(
                                        input.getHeaders()),
                                ClientSessionIdHelper.extractSessionIdFromHeaders(
                                        input.getHeaders())),
                        new AuthEmailFraudCheckBypassed.Extensions(
                                JourneyType.REGISTRATION.getValue(),
                                NowHelper.toUnixTimestamp(NowHelper.now())));

        auditService.submitAuditEvent(newAuditEvent);
    }

    private void submitEmailFraudCheckDecisionUsedAuditEvent(
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            CheckEmailFraudBlockRequest request,
            EmailCheckResultStore emailCheckResult) {
        var decision_reused =
                !Objects.equals(
                        ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders()),
                        emailCheckResult.getGovukSigninJourneyId());
        var newAuditEvent =
                AuthEmailFraudCheckDecisionUsed.create(
                        userContext.getAuthSession().getClientId(),
                        new AuthEmailFraudCheckDecisionUsed.User(
                                StructuredAuditService.UNKNOWN,
                                request.getEmail(),
                                IpAddressHelper.extractIpAddress(input),
                                PersistentIdHelper.extractPersistentIdFromHeaders(
                                        input.getHeaders()),
                                ClientSessionIdHelper.extractSessionIdFromHeaders(
                                        input.getHeaders())),
                        new AuthEmailFraudCheckDecisionUsed.Extensions(
                                JourneyType.REGISTRATION.getValue(),
                                decision_reused ? emailCheckResult.getReferenceNumber() : null,
                                emailCheckResult.getStatus().name(),
                                decision_reused,
                                decision_reused
                                        ? getEmailFraudCheckResponseJsonFromResult(emailCheckResult)
                                        : null),
                        decision_reused ? getRestrictedJsonFromResult(emailCheckResult) : null);

        auditService.submitAuditEvent(newAuditEvent);
    }
}
