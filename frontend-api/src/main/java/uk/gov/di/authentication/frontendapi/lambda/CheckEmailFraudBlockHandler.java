package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockResponse;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.ArrayList;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class CheckEmailFraudBlockHandler extends BaseFrontendHandler<CheckEmailFraudBlockRequest> {

    private static final Logger LOG = LogManager.getLogger(CheckEmailFraudBlockHandler.class);

    private final AuditService auditService;
    private final DynamoEmailCheckResultService dynamoEmailCheckResultService;

    protected CheckEmailFraudBlockHandler(
            ConfigurationService configurationService,
            ClientService clientService,
            AuthenticationService authenticationService,
            DynamoEmailCheckResultService dynamoEmailCheckResultService,
            AuditService auditService,
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
        this.auditService = new AuditService(configurationService);
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

            if (configurationService.isEmailCheckEnabled()
                    && status.equals(EmailCheckResultStatus.PENDING)) {
                submitAuditEvent(input, userContext, request);
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

    private void submitAuditEvent(
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            CheckEmailFraudBlockRequest request) {

        var sessionId =
                RequestHeaderHelper.getHeaderValueOrElse(
                        input.getHeaders(), SESSION_ID_HEADER, AuditService.UNKNOWN);

        var auditContext =
                new AuditContext(
                        userContext.getAuthSession().getClientId(),
                        ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders()),
                        sessionId,
                        AuditService.UNKNOWN,
                        request.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                        Optional.ofNullable(userContext.getTxmaAuditEncoded()),
                        new ArrayList<>());

        auditService.submitAuditEvent(
                FrontendAuditableEvent.AUTH_EMAIL_FRAUD_CHECK_BYPASSED,
                auditContext,
                AuditService.MetadataPair.pair("journey_type", JourneyType.REGISTRATION.getValue()),
                AuditService.MetadataPair.pair(
                        "assessment_checked_at_timestamp",
                        NowHelper.toUnixTimestamp(NowHelper.now())),
                AuditService.MetadataPair.pair("iss", AuditService.COMPONENT_ID));
    }
}
