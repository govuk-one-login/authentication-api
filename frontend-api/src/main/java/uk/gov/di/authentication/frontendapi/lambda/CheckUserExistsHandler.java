package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.anticorruptionlayer.DecisionErrorHttpMapper;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.LockoutInformation;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.PhoneNumberHelper.isDomesticPhoneNumber;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.mfa.MFAMethodsService.getMfaMethodOrDefaultMfaMethod;

public class CheckUserExistsHandler extends BaseFrontendHandler<CheckUserExistsRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(CheckUserExistsHandler.class);
    private final AuditService auditService;
    private final PermissionDecisionManager permissionDecisionManager;
    private final MFAMethodsService mfaMethodsService;

    public CheckUserExistsHandler(
            ConfigurationService configurationService,
            AuthSessionService authSessionService,
            AuthenticationService authenticationService,
            AuditService auditService,
            PermissionDecisionManager permissionDecisionManager,
            MFAMethodsService mfaMethodsService) {
        super(
                CheckUserExistsRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.auditService = auditService;
        this.permissionDecisionManager = permissionDecisionManager;
        this.mfaMethodsService = mfaMethodsService;
    }

    public CheckUserExistsHandler() {
        this(ConfigurationService.getInstance());
    }

    public CheckUserExistsHandler(ConfigurationService configurationService) {
        super(CheckUserExistsRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.permissionDecisionManager = new PermissionDecisionManager(configurationService);
        this.mfaMethodsService = new MFAMethodsService(configurationService);
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
            CheckUserExistsRequest request,
            UserContext userContext) {

        attachSessionIdToLogs(userContext.getAuthSession().getSessionId());

        try {
            LOG.info("Processing request");

            String emailAddress = request.getEmail().toLowerCase();
            Optional<ErrorResponse> errorResponse =
                    ValidationHelper.validateEmailAddress(emailAddress);
            String persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

            var auditContext =
                    auditContextFromUserContext(
                            userContext,
                            AuditService.UNKNOWN,
                            emailAddress,
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            persistentSessionId);

            if (errorResponse.isPresent()) {
                auditService.submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CHECK_USER_INVALID_EMAIL, auditContext);
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }

            var userProfile = authenticationService.getUserProfileByEmailMaybe(emailAddress);
            var userExists = userProfile.isPresent();
            var internalCommonSubjectId =
                    userExists
                            ? ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                            userProfile.get(),
                                            configurationService.getInternalSectorUri(),
                                            authenticationService)
                                    .getValue()
                            : AuditService.UNKNOWN;
            userContext.getAuthSession().setEmailAddress(emailAddress);

            PermissionContext permissionContext =
                    PermissionContext.builder().withEmailAddress(emailAddress).build();

            var decisionResult =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.PASSWORD_RESET, permissionContext);

            if (decisionResult.isFailure()) {
                LOG.info("No decision made: {}", decisionResult.getFailure());
                return DecisionErrorHttpMapper.toApiGatewayProxyErrorResponse(
                        decisionResult.getFailure());
            }

            if (decisionResult.getSuccess() instanceof Decision.TemporarilyLockedOut) {
                LOG.info("User account is locked");
                auditContext = auditContext.withSubjectId(internalCommonSubjectId);
                authSessionService.updateSession(userContext.getAuthSession());

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                        auditContext,
                        pair(
                                "number_of_attempts_user_allowed_to_login",
                                configurationService.getMaxPasswordRetries()));

                return generateApiGatewayProxyErrorResponse(
                        400, ErrorResponse.ACCT_TEMPORARILY_LOCKED);
            }

            AuditableEvent auditableEvent;
            var rpPairwiseId = AuditService.UNKNOWN;
            var allMfaMethods = List.<MFAMethod>of();
            var defaultMfaMethod = Optional.<MFAMethod>empty();
            var hasActivePasskey = false;

            AuthSessionItem authSession = userContext.getAuthSession();

            if (userExists) {
                auditableEvent = FrontendAuditableEvent.AUTH_CHECK_USER_KNOWN_EMAIL;
                rpPairwiseId =
                        ClientSubjectHelper.getSubject(
                                        userProfile.get(),
                                        userContext.getAuthSession(),
                                        authenticationService)
                                .getValue();

                LOG.info("Setting internal common subject identifier in user session");

                authSession.setInternalCommonSubjectId(internalCommonSubjectId);
                var userCredentials =
                        authenticationService.getUserCredentialsFromEmail(emailAddress);
                var allMfaMethodsResult =
                        mfaMethodsService.getMfaMethods(userProfile.get(), userCredentials, true);
                if (allMfaMethodsResult.isFailure()) {
                    return switch (allMfaMethodsResult.getFailure()) {
                        case UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP -> generateApiGatewayProxyErrorResponse(
                                500, ErrorResponse.AUTH_APP_MFA_ID_ERROR);
                        case USER_DOES_NOT_HAVE_ACCOUNT -> generateApiGatewayProxyErrorResponse(
                                500, ErrorResponse.ACCT_DOES_NOT_EXIST);
                        case UNKNOWN_MFA_IDENTIFIER -> generateApiGatewayProxyErrorResponse(
                                500, ErrorResponse.INVALID_MFA_METHOD);
                    };
                }
                allMfaMethods = allMfaMethodsResult.getSuccess();
                defaultMfaMethod = getMfaMethodOrDefaultMfaMethod(allMfaMethods, null, null);
                auditContext = auditContext.withSubjectId(internalCommonSubjectId);
            } else {
                authSession.setInternalCommonSubjectId(null);
                auditableEvent = FrontendAuditableEvent.AUTH_CHECK_USER_NO_ACCOUNT_WITH_EMAIL;
            }

            auditService.submitAuditEvent(
                    auditableEvent, auditContext, pair("rpPairwiseId", rpPairwiseId));

            var lockoutInformationResult = determineLockoutInformation(permissionContext);

            if (lockoutInformationResult.isFailure()) {
                return DecisionErrorHttpMapper.toApiGatewayProxyErrorResponse(
                        lockoutInformationResult.getFailure());
            }

            var lockoutInformation = lockoutInformationResult.getSuccess();

            var mfaMethodType =
                    defaultMfaMethod
                            .map(m -> MFAMethodType.valueOf(m.getMfaMethodType()))
                            .orElse(MFAMethodType.NONE);
            var phoneNumberLastThree =
                    mfaMethodType == MFAMethodType.SMS
                            ? defaultMfaMethod
                                    .map(MFAMethod::getDestination)
                                    .map(FrontendApiPhoneNumberHelper::getLastDigitsOfPhoneNumber)
                                    .orElse(null)
                            : null;
            var hasInternationalPhoneNumber =
                    allMfaMethods.stream()
                            .anyMatch(
                                    m ->
                                            MFAMethodType.SMS.name().equals(m.getMfaMethodType())
                                                    && m.getDestination() != null
                                                    && !isDomesticPhoneNumber(m.getDestination()));

            CheckUserExistsResponse checkUserExistsResponse =
                    new CheckUserExistsResponse(
                            emailAddress,
                            userExists,
                            mfaMethodType,
                            phoneNumberLastThree,
                            lockoutInformation,
                            hasActivePasskey,
                            hasInternationalPhoneNumber);

            authSessionService.updateSession(authSession);

            LOG.info("Successfully processed request");

            return generateApiGatewayProxyResponse(200, checkUserExistsResponse);

        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }
    }

    private Result<DecisionError, List<LockoutInformation>> determineLockoutInformation(
            PermissionContext permissionContext) {
        var lockoutInformation = new ArrayList<LockoutInformation>();

        var signInResult =
                permissionDecisionManager.canVerifyMfaOtp(JourneyType.SIGN_IN, permissionContext);
        if (signInResult.isFailure()) {
            return Result.failure(signInResult.getFailure());
        }
        if (signInResult.getSuccess() instanceof Decision.TemporarilyLockedOut tempLockOut) {
            long ttl = tempLockOut.lockedUntil().getEpochSecond();
            lockoutInformation.add(
                    new LockoutInformation(
                            "codeBlock", MFAMethodType.AUTH_APP, ttl, JourneyType.SIGN_IN));
        }

        var passwordResetResult =
                permissionDecisionManager.canVerifyMfaOtp(
                        JourneyType.PASSWORD_RESET_MFA, permissionContext);
        if (passwordResetResult.isFailure()) {
            return Result.failure(passwordResetResult.getFailure());
        }
        if (passwordResetResult.getSuccess() instanceof Decision.TemporarilyLockedOut tempLockOut) {
            long ttl = tempLockOut.lockedUntil().getEpochSecond();
            lockoutInformation.add(
                    new LockoutInformation(
                            "codeBlock",
                            MFAMethodType.AUTH_APP,
                            ttl,
                            JourneyType.PASSWORD_RESET_MFA));
        }

        return Result.success(lockoutInformation);
    }
}
