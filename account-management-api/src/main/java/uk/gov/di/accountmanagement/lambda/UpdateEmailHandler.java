package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
import uk.gov.di.accountmanagement.exceptions.InvalidPrincipalException;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.AuthEmailFraudCheckBypassed;
import uk.gov.di.authentication.auditevents.entity.AuthEmailFraudCheckDecisionUsed;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.exceptions.UserNotFoundException;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_AUTH;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.EmailCheckResultExtractorHelper.getEmailFraudCheckResponseJsonFromResult;
import static uk.gov.di.authentication.shared.helpers.EmailCheckResultExtractorHelper.getRestrictedJsonFromResult;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class UpdateEmailHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();
    private final DynamoService dynamoService;
    private final DynamoEmailCheckResultService dynamoEmailCheckResultService;
    private final AwsSqsClient sqsClient;
    private final CodeStorageService codeStorageService;
    private static final Logger LOG = LogManager.getLogger(UpdateEmailHandler.class);
    private final AuditService auditService;
    private final ConfigurationService configurationService;
    private final StructuredAuditService structuredAuditService;

    public UpdateEmailHandler() {
        this(ConfigurationService.getInstance());
    }

    public UpdateEmailHandler(
            DynamoService dynamoService,
            DynamoEmailCheckResultService dynamoEmailCheckResultService,
            AwsSqsClient sqsClient,
            CodeStorageService codeStorageService,
            AuditService auditService,
            ConfigurationService configurationService,
            StructuredAuditService structuredAuditService) {
        this.dynamoService = dynamoService;
        this.dynamoEmailCheckResultService = dynamoEmailCheckResultService;
        this.sqsClient = sqsClient;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.configurationService = configurationService;
        this.structuredAuditService = structuredAuditService;
    }

    public UpdateEmailHandler(ConfigurationService configurationService) {
        this.dynamoService = new DynamoService(configurationService);
        this.dynamoEmailCheckResultService =
                new DynamoEmailCheckResultService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.auditService = new AuditService(configurationService);
        this.configurationService = configurationService;
        this.structuredAuditService = new StructuredAuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> updateEmailRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent updateEmailRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        String sessionId =
                RequestHeaderHelper.getHeaderValueOrElse(input.getHeaders(), SESSION_ID_HEADER, "");
        attachTraceId();
        attachSessionIdToLogs(sessionId);
        LOG.info("UpdateEmailHandler received request");
        SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));
        try {
            UpdateEmailRequest updateInfoRequest =
                    objectMapper.readValue(input.getBody(), UpdateEmailRequest.class);

            boolean isValidOtpCode =
                    codeStorageService.isValidOtpCode(
                            updateInfoRequest.getReplacementEmailAddress(),
                            updateInfoRequest.getOtp(),
                            NotificationType.VERIFY_EMAIL);
            if (!isValidOtpCode) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.INVALID_OTP);
            }

            Optional<ErrorResponse> emailValidationErrors =
                    ValidationHelper.validateEmailAddressUpdate(
                            updateInfoRequest.getExistingEmailAddress(),
                            updateInfoRequest.getReplacementEmailAddress());
            if (emailValidationErrors.isPresent()) {
                return generateApiGatewayProxyErrorResponse(400, emailValidationErrors.get());
            }

            var accountWithReplacementEmailExists =
                    dynamoService.userExists(updateInfoRequest.getReplacementEmailAddress());
            if (accountWithReplacementEmailExists) {
                return generateApiGatewayProxyErrorResponse(
                        400, ErrorResponse.ACCT_WITH_EMAIL_EXISTS);
            }

            var userProfile =
                    dynamoService
                            .getUserProfileByEmailMaybe(updateInfoRequest.getExistingEmailAddress())
                            .orElseThrow(
                                    () ->
                                            new UserNotFoundException(
                                                    "User not found with given email"));

            var emailCheckResult =
                    dynamoEmailCheckResultService.getEmailCheckStore(
                            updateInfoRequest.getReplacementEmailAddress());

            var emailCheckResultStatus =
                    emailCheckResult
                            .map(EmailCheckResultStore::getStatus)
                            .orElse(EmailCheckResultStatus.PENDING);
            LOG.info(
                    "UpdateEmailHandler: Experian email verification status: {}",
                    emailCheckResultStatus);

            LOG.info("Calculating internal common subject identifier");
            var internalCommonSubjectIdentifier =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userProfile,
                            configurationService.getInternalSectorUri(),
                            dynamoService);

            var auditContext =
                    new AuditContext(
                            input.getRequestContext()
                                    .getAuthorizer()
                                    .getOrDefault("clientId", AuditService.UNKNOWN)
                                    .toString(),
                            ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders()),
                            sessionId,
                            internalCommonSubjectIdentifier.getValue(),
                            updateInfoRequest.getReplacementEmailAddress(),
                            IpAddressHelper.extractIpAddress(input),
                            userProfile.getPhoneNumber(),
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                            AuditHelper.getTxmaAuditEncoded(input.getHeaders()),
                            new ArrayList<>());

            if (emailCheckResultStatus.equals(EmailCheckResultStatus.PENDING)) {
                submitEmailFraudCheckBypassedAuditEvent(auditContext);
            } else {
                emailCheckResult.ifPresent(
                        result ->
                                submitEmailFraudCheckDecisionUsedAuditEvent(auditContext, result));
            }

            if (emailCheckResultStatus == EmailCheckResultStatus.DENY) {
                return generateApiGatewayProxyErrorResponse(
                        403, ErrorResponse.EMAIL_ADDRESS_DENIED);
            }

            Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
            if (PrincipalValidationHelper.principalIsInvalid(
                    userProfile,
                    configurationService.getInternalSectorUri(),
                    dynamoService,
                    authorizerParams)) {
                throw new InvalidPrincipalException("Invalid Principal in request");
            }
            dynamoService.updateEmail(
                    updateInfoRequest.getExistingEmailAddress(),
                    updateInfoRequest.getReplacementEmailAddress());
            LOG.info(
                    "Email has successfully been updated. Adding message to SQS queue (x2 - notification will be sent to current and previous email addresses)");

            String[] emailUpdateNotificationDestinations = {
                updateInfoRequest.getExistingEmailAddress(),
                updateInfoRequest.getReplacementEmailAddress()
            };
            for (String emailAddress : emailUpdateNotificationDestinations) {
                NotifyRequest notifyEmailAddressUpdateRequest =
                        new NotifyRequest(
                                emailAddress, NotificationType.EMAIL_UPDATED, userLanguage);
                sqsClient.send(objectMapper.writeValueAsString((notifyEmailAddressUpdateRequest)));
            }

            auditService.submitAuditEvent(
                    AccountManagementAuditableEvent.AUTH_UPDATE_EMAIL,
                    auditContext.withSubjectId(internalCommonSubjectIdentifier.getValue()),
                    AUDIT_EVENT_COMPONENT_ID_AUTH,
                    AuditService.MetadataPair.pair(
                            "replacedEmail", updateInfoRequest.getExistingEmailAddress(), true));

            LOG.info("Message successfully added to queue. Generating successful gateway response");
            return generateEmptySuccessApiGatewayResponse();
        } catch (UserNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ACCT_DOES_NOT_EXIST);
        } catch (JsonException | IllegalArgumentException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }
    }

    private void submitEmailFraudCheckBypassedAuditEvent(AuditContext auditContext) {
        var newAuditEvent =
                AuthEmailFraudCheckBypassed.create(
                        auditContext.clientId(),
                        new AuthEmailFraudCheckBypassed.User(
                                auditContext.subjectId(),
                                auditContext.email(),
                                auditContext.ipAddress(),
                                auditContext.persistentSessionId(),
                                auditContext.sessionId()),
                        new AuthEmailFraudCheckBypassed.Extensions(
                                JourneyType.REGISTRATION.getValue(),
                                NowHelper.toUnixTimestamp(NowHelper.now())));

        structuredAuditService.submitAuditEvent(newAuditEvent);
    }

    private void submitEmailFraudCheckDecisionUsedAuditEvent(
            AuditContext auditContext, EmailCheckResultStore emailCheckResult) {
        var decision_reused =
                !Objects.equals(
                        auditContext.sessionId(), emailCheckResult.getGovukSigninJourneyId());
        var newAuditEvent =
                AuthEmailFraudCheckDecisionUsed.create(
                        auditContext.clientId(),
                        new AuthEmailFraudCheckDecisionUsed.User(
                                auditContext.subjectId(),
                                auditContext.email(),
                                auditContext.ipAddress(),
                                auditContext.persistentSessionId(),
                                auditContext.sessionId()),
                        new AuthEmailFraudCheckDecisionUsed.Extensions(
                                JourneyType.REGISTRATION.getValue(),
                                decision_reused ? emailCheckResult.getReferenceNumber() : null,
                                emailCheckResult.getStatus().name(),
                                decision_reused,
                                decision_reused
                                        ? getEmailFraudCheckResponseJsonFromResult(emailCheckResult)
                                        : null),
                        decision_reused ? getRestrictedJsonFromResult(emailCheckResult) : null);

        structuredAuditService.submitAuditEvent(newAuditEvent);
    }
}
