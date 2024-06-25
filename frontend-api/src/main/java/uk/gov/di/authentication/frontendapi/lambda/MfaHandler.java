package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaRequest;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.TestClientHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Locale;
import java.util.Optional;

import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.MFA_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.MFA_MISMATCHED_EMAIL;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.MFA_MISSING_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1000;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1002;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1014;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class MfaHandler extends BaseFrontendHandler<MfaRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(MfaHandler.class);

    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final AwsSqsClient sqsClient;

    public MfaHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            AwsSqsClient sqsClient) {
        super(
                MfaRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.sqsClient = sqsClient;
    }

    public MfaHandler(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        super(MfaRequest.class, configurationService, redisConnectionService);
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService =
                new CodeStorageService(configurationService, redisConnectionService);
        this.auditService = new AuditService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
    }

    public MfaHandler() {
        super(MfaRequest.class, ConfigurationService.getInstance());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService = new CodeStorageService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
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
            MfaRequest request,
            UserContext userContext) {
        try {
            String persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

            attachSessionIdToLogs(userContext.getSession().getSessionId());

            LOG.info("MfaHandler received request");

            String email = request.getEmail().toLowerCase(Locale.ROOT);
            JourneyType journeyType =
                    request.getJourneyType() != null
                            ? request.getJourneyType()
                            : JourneyType.SIGN_IN;

            var auditContext =
                    new AuditContext(
                            userContext.getClientId(),
                            userContext.getClientSessionId(),
                            userContext.getSession().getSessionId(),
                            userContext.getSession().getInternalCommonSubjectIdentifier(),
                            email,
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            persistentSessionId,
                            Optional.ofNullable(userContext.getTxmaAuditEncoded()));

            var metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair("journey-type", journeyType),
                        pair("mfa-type", MFAMethodType.SMS.getValue())
                    };

            if (!CodeRequestType.isValidCodeRequestType(
                    NotificationType.MFA_SMS.getMfaMethodType(), journeyType)) {
                LOG.warn(
                        "Invalid MFA Type '{}' for journey '{}'",
                        NotificationType.MFA_SMS.getMfaMethodType().getValue(),
                        journeyType.getValue());
                return generateApiGatewayProxyErrorResponse(400, ERROR_1002);
            }

            Optional<ErrorResponse> codeRequestValid =
                    validateCodeRequestAttempts(email, journeyType, userContext);

            if (codeRequestValid.isPresent()) {
                auditService.submitAuditEvent(
                        MFA_INVALID_CODE_REQUEST, auditContext, metadataPairs);

                return generateApiGatewayProxyErrorResponse(400, codeRequestValid.get());
            }

            if (!userContext.getSession().validateSession(email)) {
                LOG.warn("Email does not match Email in Request");
                auditService.submitAuditEvent(MFA_MISMATCHED_EMAIL, auditContext, metadataPairs);

                return generateApiGatewayProxyErrorResponse(400, ERROR_1000);
            }
            String phoneNumber = authenticationService.getPhoneNumber(email).orElse(null);

            if (phoneNumber == null) {
                auditService.submitAuditEvent(
                        MFA_MISSING_PHONE_NUMBER, auditContext, metadataPairs);
                return generateApiGatewayProxyErrorResponse(400, ERROR_1014);
            } else {
                auditContext = auditContext.withPhoneNumber(phoneNumber);
            }

            var notificationType = (request.isResendCodeRequest()) ? VERIFY_PHONE_NUMBER : MFA_SMS;

            String code =
                    codeStorageService
                            .getOtpCode(email, notificationType)
                            .orElseGet(
                                    () -> {
                                        LOG.info("No existing OTP found; generating new code");
                                        String newCode = codeGeneratorService.sixDigitCode();
                                        codeStorageService.saveOtpCode(
                                                email,
                                                newCode,
                                                configurationService.getDefaultOtpCodeExpiry(),
                                                notificationType);
                                        return newCode;
                                    });

            LOG.info("Incrementing code request count");
            sessionService.save(
                    userContext
                            .getSession()
                            .incrementCodeRequestCount(NotificationType.MFA_SMS, journeyType));
            AuditableEvent auditableEvent;
            if (TestClientHelper.isTestClientWithAllowedEmail(userContext, configurationService)) {
                LOG.info(
                        "MfaHandler not sending message with NotificationType {}",
                        notificationType);
                auditableEvent = FrontendAuditableEvent.MFA_CODE_SENT_FOR_TEST_CLIENT;
            } else {
                LOG.info("Placing message on queue with NotificationType {}", notificationType);
                var notifyRequest =
                        new NotifyRequest(
                                phoneNumber, notificationType, code, userContext.getUserLanguage());
                sqsClient.send(objectMapper.writeValueAsString(notifyRequest));
                auditableEvent = FrontendAuditableEvent.MFA_CODE_SENT;
            }

            auditService.submitAuditEvent(auditableEvent, auditContext, metadataPairs);
            LOG.info("Successfully processed request");

            return generateEmptySuccessApiGatewayResponse();
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
        } catch (ClientNotFoundException e) {
            LOG.warn("Client not found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private Optional<ErrorResponse> validateCodeRequestAttempts(
            String email, JourneyType journeyType, UserContext userContext) {
        Session session = userContext.getSession();
        var codeRequestCount = session.getCodeRequestCount(MFA_SMS, journeyType);
        LOG.info("CodeRequestCount is: {}", codeRequestCount);
        var codeRequestType = CodeRequestType.getCodeRequestType(MFA_SMS, journeyType);
        var newCodeRequestBlockPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
        var newCodeBlockPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        if (codeRequestCount == configurationService.getCodeMaxRetries()) {
            LOG.info(
                    "User has requested too many OTP codes. Setting block with prefix: {}",
                    newCodeRequestBlockPrefix);
            codeStorageService.saveBlockedForEmail(
                    email, newCodeRequestBlockPrefix, configurationService.getLockoutDuration());
            LOG.info("Resetting code request count");
            sessionService.save(
                    session.resetCodeRequestCount(NotificationType.MFA_SMS, journeyType));
            return Optional.of(ErrorResponse.ERROR_1025);
        }
        if (codeStorageService.isBlockedForEmail(email, newCodeRequestBlockPrefix)) {
            LOG.info(
                    "User is blocked from requesting any OTP codes. Code request block prefix: {}",
                    newCodeRequestBlockPrefix);
            return Optional.of(ErrorResponse.ERROR_1026);
        }
        if (codeStorageService.isBlockedForEmail(email, newCodeBlockPrefix)) {
            LOG.info(
                    "User is blocked from entering any OTP codes. Code attempt block prefix: {}",
                    newCodeBlockPrefix);
            return Optional.of(ErrorResponse.ERROR_1027);
        }
        return Optional.empty();
    }
}
