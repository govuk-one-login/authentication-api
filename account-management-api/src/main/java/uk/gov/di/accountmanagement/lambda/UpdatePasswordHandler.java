package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdatePasswordRequest;
import uk.gov.di.accountmanagement.exceptions.InvalidPrincipalException;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.exceptions.UserNotFoundException;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.validation.PasswordValidator;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_UPDATE_PASSWORD;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class UpdatePasswordHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final AuditService auditService;
    private final ConfigurationService configurationService;
    private final CommonPasswordsService commonPasswordsService;
    private final PasswordValidator passwordValidator;

    private static final Logger LOG = LogManager.getLogger(UpdatePasswordHandler.class);

    public UpdatePasswordHandler() {
        this(ConfigurationService.getInstance());
    }

    public UpdatePasswordHandler(
            DynamoService dynamoService,
            AwsSqsClient sqsClient,
            AuditService auditService,
            CommonPasswordsService commonPasswordsService,
            PasswordValidator passwordValidator,
            ConfigurationService configurationService) {
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
        this.auditService = auditService;
        this.commonPasswordsService = commonPasswordsService;
        this.passwordValidator = passwordValidator;
        this.configurationService = configurationService;
    }

    public UpdatePasswordHandler(ConfigurationService configurationService) {
        this.dynamoService = new DynamoService(ConfigurationService.getInstance());
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.auditService = new AuditService(configurationService);
        this.commonPasswordsService = new CommonPasswordsService(configurationService);
        this.passwordValidator = new PasswordValidator(commonPasswordsService);
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> updatePasswordRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent updatePasswordRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        String sessionId =
                RequestHeaderHelper.getHeaderValueOrElse(input.getHeaders(), SESSION_ID_HEADER, "");
        attachSessionIdToLogs(sessionId);
        LOG.info("UpdatePasswordHandler received request");
        SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));
        context.getClientContext();
        try {
            UpdatePasswordRequest updatePasswordRequest =
                    objectMapper.readValue(input.getBody(), UpdatePasswordRequest.class);

            Optional<ErrorResponse> passwordValidationError =
                    passwordValidator.validate(updatePasswordRequest.getNewPassword());

            if (passwordValidationError.isPresent()) {
                LOG.info("Error message: {}", passwordValidationError.get().getMessage());
                return generateApiGatewayProxyErrorResponse(400, passwordValidationError.get());
            }
            var userProfile =
                    dynamoService
                            .getUserProfileByEmailMaybe(updatePasswordRequest.getEmail())
                            .orElseThrow(
                                    () ->
                                            new UserNotFoundException(
                                                    "User not found with given email"));

            Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();

            if (PrincipalValidationHelper.principalIsInvalid(
                    userProfile,
                    configurationService.getInternalSectorUri(),
                    dynamoService,
                    authorizerParams)) {
                throw new InvalidPrincipalException("Invalid Principal in request");
            }

            String currentPassword =
                    dynamoService
                            .getUserCredentialsFromEmail(updatePasswordRequest.getEmail())
                            .getPassword();

            if (isNewPasswordSameAsCurrentPassword(
                    currentPassword, updatePasswordRequest.getNewPassword())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1024);
            }

            dynamoService.updatePassword(
                    updatePasswordRequest.getEmail(), updatePasswordRequest.getNewPassword());

            LOG.info(
                    "User Password has successfully been updated.  Adding confirmation message to SQS queue");
            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            updatePasswordRequest.getEmail(),
                            NotificationType.PASSWORD_UPDATED,
                            userLanguage);
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            LOG.info("Message successfully added to queue. Generating successful gateway response");

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
                            userProfile.getEmail(),
                            IpAddressHelper.extractIpAddress(input),
                            userProfile.getPhoneNumber(),
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                            AuditHelper.getTxmaAuditEncoded(input.getHeaders()));

            auditService.submitAuditEvent(AUTH_UPDATE_PASSWORD, auditContext);

            return generateEmptySuccessApiGatewayResponse();

        } catch (UserNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1010);
        } catch (JsonException | IllegalArgumentException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private static boolean isNewPasswordSameAsCurrentPassword(
            String hashedPassword, String password) {
        return Argon2MatcherHelper.matchRawStringWithEncoded(password, hashedPassword);
    }
}
