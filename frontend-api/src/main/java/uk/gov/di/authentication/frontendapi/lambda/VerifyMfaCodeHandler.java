package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.shared.validation.MfaCodeValidatorFactory;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.util.Map.entry;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_VERIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.INVALID_CODE_SENT;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public class VerifyMfaCodeHandler extends BaseFrontendHandler<VerifyMfaCodeRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(VerifyMfaCodeHandler.class);
    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final MfaCodeValidatorFactory mfaCodeValidatorFactory;

    public VerifyMfaCodeHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            MfaCodeValidatorFactory mfaCodeValidatorFactory) {
        super(
                VerifyMfaCodeRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.mfaCodeValidatorFactory = mfaCodeValidatorFactory;
    }

    public VerifyMfaCodeHandler() {
        this(ConfigurationService.getInstance());
    }

    public VerifyMfaCodeHandler(ConfigurationService configurationService) {
        super(VerifyMfaCodeRequest.class, configurationService);
        this.codeStorageService = new CodeStorageService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.mfaCodeValidatorFactory =
                new MfaCodeValidatorFactory(
                        configurationService,
                        codeStorageService,
                        new DynamoService(configurationService));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            VerifyMfaCodeRequest codeRequest,
            UserContext userContext) {

        var clientSessionId =
                getHeaderValueFromHeaders(
                        input.getHeaders(),
                        CLIENT_SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        attachLogFieldToLogs(
                PERSISTENT_SESSION_ID, extractPersistentIdFromHeaders(input.getHeaders()));
        attachLogFieldToLogs(
                CLIENT_ID,
                userContext.getClient().map(ClientRegistry::getClientID).orElse("unknown"));

        LOG.info("Invoking verify MFA code handler");

        try {
            var session = userContext.getSession();
            var mfaMethodType = codeRequest.getMfaMethodType();
            var isRegistration = codeRequest.isRegistration();

            var mfaCodeValidator =
                    mfaCodeValidatorFactory
                            .getMfaCodeValidator(mfaMethodType, isRegistration, userContext)
                            .orElse(null);

            if (Objects.isNull(mfaCodeValidator)) {
                LOG.info("No MFA code validator found for this MFA method type");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1002);
            }

            var errorResponse = mfaCodeValidator.validateCode(codeRequest.getCode());

            processCodeSession(
                    errorResponse,
                    session,
                    mfaMethodType,
                    input,
                    context,
                    userContext,
                    isRegistration);

            sessionService.save(session);

            return errorResponse
                    .map(response -> generateApiGatewayProxyErrorResponse(400, response))
                    .orElseGet(
                            () -> {
                                LOG.info(
                                        "MFA code has been successfully verified for MFA type: {}. RegistrationJourney: {}",
                                        MFAMethodType.AUTH_APP.getValue(),
                                        codeRequest.isRegistration());
                                sessionService.save(
                                        session.setVerifiedMfaMethodType(MFAMethodType.AUTH_APP));
                                return ApiGatewayResponseHelper
                                        .generateEmptySuccessApiGatewayResponse();
                            });

        } catch (Exception e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private FrontendAuditableEvent errorResponseAsFrontendAuditableEvent(
            Optional<ErrorResponse> errorResponse) {

        if (errorResponse.isEmpty()) {
            return CODE_VERIFIED;
        }

        Map<ErrorResponse, FrontendAuditableEvent> map =
                Map.ofEntries(
                        entry(ErrorResponse.ERROR_1042, CODE_MAX_RETRIES_REACHED),
                        entry(ErrorResponse.ERROR_1043, INVALID_CODE_SENT));

        if (map.containsKey(errorResponse.get())) {
            return map.get(errorResponse.get());
        }

        return INVALID_CODE_SENT;
    }

    private void processCodeSession(
            Optional<ErrorResponse> errorResponse,
            Session session,
            MFAMethodType mfaMethodType,
            APIGatewayProxyRequestEvent input,
            Context context,
            UserContext userContext,
            boolean isRegistration) {

        var auditableEvent = errorResponseAsFrontendAuditableEvent(errorResponse);

        if (isRegistration && errorResponse.isEmpty()) {
            authenticationService.setMFAMethodVerifiedTrue(
                    session.getEmailAddress(), mfaMethodType);
            authenticationService.setAccountVerified(session.getEmailAddress());
        }

        if (ErrorResponse.ERROR_1042.equals(errorResponse.orElse(null))) {
            blockCodeForSessionAndResetCount(session);
        }

        auditService.submitAuditEvent(
                auditableEvent,
                context.getAwsRequestId(),
                session.getSessionId(),
                userContext
                        .getClient()
                        .map(ClientRegistry::getClientID)
                        .orElse(AuditService.UNKNOWN),
                userContext
                        .getUserProfile()
                        .map(UserProfile::getSubjectID)
                        .orElse(AuditService.UNKNOWN),
                session.getEmailAddress(),
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                extractPersistentIdFromHeaders(input.getHeaders()),
                pair("mfa-type", mfaMethodType.getValue()));
    }

    private void blockCodeForSessionAndResetCount(Session session) {
        codeStorageService.saveBlockedForEmail(
                session.getEmailAddress(),
                CODE_BLOCKED_KEY_PREFIX,
                configurationService.getBlockedEmailDuration());
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(session.getEmailAddress());
    }
}
