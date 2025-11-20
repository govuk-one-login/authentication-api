package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.anticorruptionlayer.DecisionErrorHttpMapper;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.conditions.TermsAndConditionsHelper;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.TestUserHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import java.util.Map;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_NO_ACCOUNT_WITH_EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper.redactPhoneNumber;
import static uk.gov.di.authentication.frontendapi.helpers.MfaMethodResponseConverterHelper.convertMfaMethodsToMfaMethodResponse;
import static uk.gov.di.authentication.frontendapi.services.UserMigrationService.userHasBeenPartlyMigrated;
import static uk.gov.di.authentication.shared.conditions.MfaHelper.getUserMFADetail;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

/**
 * Refactored LoginHandler demonstrating method chaining with the existing Result pattern.
 * This shows how the complex nested logic can be simplified using functional composition.
 * 
 * TESTING APPROACH:
 * Use TDD with public methods first, then extract private methods during refactoring.
 * Test all scenarios through handleRequestWithUserContext by mocking dependencies
 * and crafting specific inputs to exercise each validation path.
 * 
 * BENEFITS OF THIS REFACTOR:
 * 
 * Code Structure & Readability:
 * - Eliminates deep nesting: Original had 4+ levels of if/else, now linear chain
 * - Clear flow: setupLogging -> validateUserExists -> createContext -> checkPermission -> validateCredentials -> retrieveMfaMethods -> buildResponse
 * - Single responsibility: Each method does one thing and returns a Result
 * - Reduced complexity: Main method is 1 statement vs original's 200+ lines
 * 
 * Error Handling:
 * - Consistent error propagation: All errors flow through Result type automatically
 * - No scattered return statements: Error handling centralized in fold() call
 * - Type-safe errors: LoginError encapsulates status code and ErrorResponse
 * - Early termination: Failed steps automatically short-circuit the chain
 * 
 * Maintainability:
 * - Composable functions: Easy to add/remove/reorder validation steps
 * - Immutable data flow: No shared mutable state between steps
 * - Clear contracts: Each method's input/output types are explicit
 * - Easier debugging: Can inspect Result at each step in the chain
 * 
 * Testing Benefits:
 * - Black-box testing: Test behavior through public interface, not implementation details
 * - Mockable dependencies: Pure functions easier to mock/stub at service layer
 * - Predictable outcomes: Given inputs always produce same Result
 * - Edge case testing: Craft inputs to trigger specific validation failures (e.g., missing user)
 * - Behavioral verification: Test what the handler does, not how it does it
 * - Refactoring safety: Private method changes don't break tests
 * - Reduced test complexity: Single entry point with clear input/output contract
 * - TDD-friendly: Start with public methods, extract private methods during refactoring
 * - Better encapsulation: Private methods remain implementation details
 */
public class RefactoredLoginHandler extends BaseFrontendHandler<LoginRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(RefactoredLoginHandler.class);
    private final UserMigrationService userMigrationService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final CommonPasswordsService commonPasswordsService;
    private final AuthenticationAttemptsService authenticationAttemptsService;
    private final MFAMethodsService mfaMethodsService;
    private final PermissionDecisionManager permissionDecisionManager;
    private final UserActionsManager userActionsManager;
    private final TestUserHelper testUserHelper;

    public RefactoredLoginHandler(ConfigurationService configurationService) {
        super(LoginRequest.class, configurationService, true);
        var codeStorageService = new CodeStorageService(configurationService);
        this.userMigrationService = new UserMigrationService(new DynamoService(configurationService), configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.commonPasswordsService = new CommonPasswordsService(configurationService);
        this.authenticationAttemptsService = new AuthenticationAttemptsService(configurationService);
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.permissionDecisionManager = new PermissionDecisionManager(configurationService, codeStorageService, authenticationAttemptsService);
        this.userActionsManager = new UserActionsManager(configurationService, codeStorageService, this.authSessionService, this.authenticationAttemptsService);
        this.testUserHelper = new TestUserHelper(configurationService);
    }

    public RefactoredLoginHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            LoginRequest request,
            UserContext userContext) {

        return fold(
            setupLogging(request, userContext)
                .flatMap(journeyType -> validateUserExists(request, userContext, input, journeyType))
                .flatMap(this::createUserPermissionContext)
                .flatMap(this::checkPasswordPermission)
                .flatMap(ctx -> validateCredentials(ctx, request, input))
                .flatMap(this::retrieveMfaMethods)
                .flatMap(ctx -> buildLoginResponse(ctx, request)),
            error -> generateApiGatewayProxyErrorResponse(error.statusCode(), error.errorResponse()),
            response -> response
        );
    }

    private Result<LoginError, JourneyType> setupLogging(LoginRequest request, UserContext userContext) {
        attachSessionIdToLogs(userContext.getAuthSession().getSessionId());
        var journeyType = request.getJourneyType() != null ? request.getJourneyType() : JourneyType.SIGN_IN;
        attachLogFieldToLogs(JOURNEY_TYPE, journeyType != null ? journeyType.getValue() : "missing");
        return Result.success(journeyType);
    }

    private Result<LoginError, LoginContext> validateUserExists(LoginRequest request, UserContext userContext, APIGatewayProxyRequestEvent input, JourneyType journeyType) {
        var userProfileMaybe = authenticationService.getUserProfileByEmailMaybe(request.getEmail());
        
        if (userProfileMaybe.isEmpty() || userContext.getUserCredentials().isEmpty()) {
            var auditContext = auditContextFromUserContext(
                userContext,
                AuditService.UNKNOWN,
                request.getEmail(),
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));
            
            auditService.submitAuditEvent(AUTH_NO_ACCOUNT_WITH_EMAIL, auditContext);
            return Result.failure(new LoginError(400, ErrorResponse.ACCT_DOES_NOT_EXIST));
        }
        
        return Result.success(new LoginContext(null, userProfileMaybe.get(), userContext, journeyType, null));
    }

    private Result<LoginError, LoginContext> createUserPermissionContext(LoginContext context) {
        var calculatedPairwiseId = ClientSubjectHelper.getSubject(
            context.userProfile(), context.userContext().getAuthSession(), authenticationService).getValue();
        
        var permissionContext = new UserPermissionContext(
            context.userProfile().getSubjectID(),
            calculatedPairwiseId,
            context.userProfile().getEmail(),
            null);
            
        return Result.success(context.withPermissionContext(permissionContext));
    }

    private Result<LoginError, LoginContext> checkPasswordPermission(LoginContext context) {
        var decisionResult = permissionDecisionManager.canReceivePassword(context.journeyType(), context.permissionContext());
        
        if (decisionResult.isFailure()) {
            LOG.error("Failure to get canReceivePassword decision due to {}", decisionResult.getFailure());
            var httpResponse = DecisionErrorHttpMapper.toHttpResponse(decisionResult.getFailure());
            return Result.failure(new LoginError(httpResponse.statusCode(), httpResponse.errorResponse()));
        }
        
        var decision = decisionResult.getSuccess();
        if (decision instanceof Decision.TemporarilyLockedOut) {
            return Result.failure(new LoginError(400, ErrorResponse.TOO_MANY_INVALID_PW_ENTERED));
        }
        
        if (!(decision instanceof Decision.Permitted)) {
            return Result.failure(new LoginError(500, ErrorResponse.UNHANDLED_NEGATIVE_DECISION));
        }
        
        return Result.success(context);
    }

    private Result<LoginError, LoginContext> validateCredentials(
            LoginContext context,
            LoginRequest request,
            APIGatewayProxyRequestEvent input) {
        
        if (!credentialsAreValid(request, context.userProfile())) {
            return handleInvalidCredentials(context, input);
        }
        
        recordSuccessMetrics(context.userContext(), context.userProfile());
        return Result.success(context);
    }

    private Result<LoginError, LoginContext> retrieveMfaMethods(LoginContext context) {
        var retrieveMfaMethods = mfaMethodsService.getMfaMethods(context.userProfile().getEmail());
        if (retrieveMfaMethods.isFailure()) {
            return Result.failure(new LoginError(500, ErrorResponse.MFA_METHODS_RETRIEVAL_ERROR));
        }
        
        var mfaMethodResponses = convertMfaMethodsToMfaMethodResponse(retrieveMfaMethods.getSuccess());
        if (mfaMethodResponses.isFailure()) {
            return Result.failure(new LoginError(500, ErrorResponse.MFA_METHODS_RETRIEVAL_ERROR));
        }
        
        return Result.success(context.withMfaMethodResponses(mfaMethodResponses.getSuccess()));
    }

    private Result<LoginError, APIGatewayProxyResponseEvent> buildLoginResponse(LoginContext context, LoginRequest request) {
        var userCredentials = context.userContext().getUserCredentials().get();
        var authSession = context.userContext().getAuthSession();
        var userProfile = context.userProfile();
        
        var userMfaDetail = getUserMFADetail(
            authSession.getRequestedCredentialStrength(),
            userCredentials,
            userProfile);
        
        boolean termsAndConditionsAccepted = isTermsAndConditionsAccepted(authSession, userProfile);
        boolean isPasswordChangeRequired = isPasswordResetRequired(request.getPassword());
        
        String redactedPhoneNumber = userMfaDetail.phoneNumber() != null && userMfaDetail.mfaMethodVerified()
            ? redactPhoneNumber(userMfaDetail.phoneNumber()) : null;
        
        try {
            var response = generateApiGatewayProxyResponse(200, new LoginResponse(
                redactedPhoneNumber,
                userMfaDetail,
                termsAndConditionsAccepted,
                context.mfaMethodResponses(),
                isPasswordChangeRequired));
            return Result.success(response);
        } catch (JsonException e) {
            return Result.failure(new LoginError(400, ErrorResponse.REQUEST_MISSING_PARAMS));
        }
    }

    private Result<LoginError, LoginContext> handleInvalidCredentials(
            LoginContext context,
            APIGatewayProxyRequestEvent input) {
        
        userActionsManager.incorrectPasswordReceived(context.journeyType(), context.permissionContext());
        
        var isReauthJourney = context.journeyType() == JourneyType.REAUTHENTICATION;
        
        if (isReauthJourney) {
            cloudwatchMetricsService.incrementCounter(
                CloudwatchMetrics.REAUTH_FAILED.getValue(),
                Map.of(
                    ENVIRONMENT.getValue(), configurationService.getEnvironment(),
                    FAILURE_REASON.getValue(), "INCORRECT_PASSWORD"));
        }
        
        return Result.failure(new LoginError(401, ErrorResponse.INVALID_LOGIN_CREDS));
    }

    private void recordSuccessMetrics(UserContext userContext, UserProfile userProfile) {
        var userCredentials = userContext.getUserCredentials().get();
        var authSession = userContext.getAuthSession();
        
        var userMfaDetail = getUserMFADetail(
            authSession.getRequestedCredentialStrength(),
            userCredentials,
            userProfile);
        
        if (!userMfaDetail.isMfaRequired()) {
            cloudwatchMetricsService.incrementAuthenticationSuccessWithoutMfa(
                AuthSessionItem.AccountState.EXISTING,
                authSession.getClientId(),
                authSession.getClientName(),
                "P0",
                testUserHelper.isTestJourney(userProfile.getEmail()));
        }
    }

    private boolean credentialsAreValid(LoginRequest request, UserProfile userProfile) {
        var userCredentials = authenticationService.getUserCredentialsFromEmail(request.getEmail());
        var userIsAMigratedUser = userHasBeenPartlyMigrated(userProfile.getLegacySubjectID(), userCredentials);
        
        if (userIsAMigratedUser) {
            return userMigrationService.processMigratedUser(userCredentials, request.getPassword());
        } else {
            return authenticationService.login(userCredentials, request.getPassword());
        }
    }

    private boolean isPasswordResetRequired(String password) {
        try {
            return commonPasswordsService.isCommonPassword(password);
        } catch (Exception e) {
            LOG.error("Unable to check if password was a common password");
            return false;
        }
    }

    private boolean isTermsAndConditionsAccepted(AuthSessionItem authSession, UserProfile userProfile) {
        if (userProfile.getTermsAndConditions() == null) {
            return false;
        }
        return TermsAndConditionsHelper.hasTermsAndConditionsBeenAccepted(
            userProfile.getTermsAndConditions(),
            configurationService.getTermsAndConditionsVersion(),
            authSession.getIsSmokeTest());
    }

    private <F, S> S fold(Result<F, S> result, java.util.function.Function<F, S> onFailure, java.util.function.Function<S, S> onSuccess) {
        return result.isSuccess() ? onSuccess.apply(result.getSuccess()) : onFailure.apply(result.getFailure());
    }

    private record LoginError(int statusCode, ErrorResponse errorResponse) {}
    
    private record LoginContext(
        UserPermissionContext permissionContext,
        UserProfile userProfile,
        UserContext userContext,
        JourneyType journeyType,
        Object mfaMethodResponses
    ) {
        public LoginContext withPermissionContext(UserPermissionContext permissionContext) {
            return new LoginContext(permissionContext, userProfile, userContext, journeyType, mfaMethodResponses);
        }
        
        public LoginContext withMfaMethodResponses(Object mfaMethodResponses) {
            return new LoginContext(permissionContext, userProfile, userContext, journeyType, mfaMethodResponses);
        }
    }
}