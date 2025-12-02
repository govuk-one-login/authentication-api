package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.anticorruptionlayer.DecisionErrorHttpMapper;
import uk.gov.di.authentication.frontendapi.anticorruptionlayer.ForbiddenReasonAntiCorruption;
import uk.gov.di.authentication.frontendapi.anticorruptionlayer.TrackingErrorHttpMapper;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckReauthUserRequest;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_ACCOUNT_IDENTIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ATTEMPT_NO_FAILED_AT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.USER_NOT_FOUND;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class CheckReAuthUserHandler extends BaseFrontendHandler<CheckReauthUserRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(CheckReAuthUserHandler.class);

    private final AuditService auditService;
    private final AuthenticationAttemptsService authenticationAttemptsService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final UserActionsManager userActionsManager;
    private final PermissionDecisionManager permissionDecisionManager;

    public CheckReAuthUserHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuditService auditService,
            AuthenticationAttemptsService authenticationAttemptsService,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuthSessionService authSessionService,
            UserActionsManager userActionsManager,
            PermissionDecisionManager permissionDecisionManager) {
        super(
                CheckReauthUserRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.auditService = auditService;
        this.authenticationAttemptsService = authenticationAttemptsService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.userActionsManager = userActionsManager;
        this.permissionDecisionManager = permissionDecisionManager;
    }

    public CheckReAuthUserHandler(
            ConfigurationService configurationService,
            CodeStorageService codeStorageService,
            AuthenticationAttemptsService authenticationAttemptsService,
            AuthSessionService authSessionService) {
        this(
                configurationService,
                new DynamoService(configurationService),
                new AuditService(configurationService),
                authenticationAttemptsService,
                new CloudwatchMetricsService(),
                authSessionService,
                new UserActionsManager(
                        configurationService,
                        codeStorageService,
                        authSessionService,
                        authenticationAttemptsService),
                new PermissionDecisionManager(
                        configurationService, codeStorageService, authenticationAttemptsService));
    }

    public CheckReAuthUserHandler(ConfigurationService configurationService) {
        this(
                configurationService,
                new CodeStorageService(configurationService),
                new AuthenticationAttemptsService(configurationService),
                new AuthSessionService(configurationService));
    }

    public CheckReAuthUserHandler() {
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
            CheckReauthUserRequest request,
            UserContext userContext) {

        var internalPairwiseId = userContext.getAuthSession().getInternalCommonSubjectId();

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        internalPairwiseId,
                        userContext.getAuthSession().getEmailAddress(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        var pairwiseIdMetadataPair = pair("rpPairwiseId", request.rpPairwiseId());

        Optional<UserProfile> maybeUserProfileOfUserSuppliedEmail =
                authenticationService.getUserProfileByEmailMaybe(request.email());

        Optional<UserProfile> maybeUserProfileOfSignedInUser = userContext.getUserProfile();

        if (maybeUserProfileOfUserSuppliedEmail.isEmpty()) {
            return generateErrorResponse(
                    maybeUserProfileOfSignedInUser,
                    request.rpPairwiseId(),
                    auditContext,
                    pairwiseIdMetadataPair,
                    request.email(),
                    maybeUserProfileOfUserSuppliedEmail);
        }

        var userProfileOfUserSuppliedEmail = maybeUserProfileOfUserSuppliedEmail.get();

        /*
           A few things go on here right now. There may be opportunity to refactor further to simplify. First, in
           order to verify the reauthentication we need to generate a pairwiseId if we have a user profile with
           the same email address that the user submitted. Then we compare that to the pairwiseId the RP submitted.
           If they are the same then it's a match.

           Once we know if there is a match or not we can check for lockouts against up to 3 identifiers:
           - We always look for lockouts against the rpPairwiseId.
           - If the user is signed in we also look for lockouts against that user.
           - If there is a match then we also look for lockouts against the matched user.

           The user profiles we check may not necessarily be the same. In theory the user could be signed in to
           auth with a different user profile than the one the RP is wanting to reauthenticate. We should be
           checking for lockouts against both users in that case.
        */
        var calculatedPairwiseIdFromUserSuppliedEmail =
                ClientSubjectHelper.getSubject(
                                userProfileOfUserSuppliedEmail,
                                userContext.getAuthSession(),
                                authenticationService)
                        .getValue();
        boolean isTheUserSubmittedEmailAssociatedWithTheRpSubmittedPairwiseId =
                calculatedPairwiseIdFromUserSuppliedEmail != null
                        && calculatedPairwiseIdFromUserSuppliedEmail.equals(request.rpPairwiseId());

        var userPermissionContext =
                UserPermissionContext.builder()
                        .withInternalSubjectIds(
                                Arrays.asList(
                                        isTheUserSubmittedEmailAssociatedWithTheRpSubmittedPairwiseId
                                                ? userProfileOfUserSuppliedEmail.getSubjectID()
                                                : null,
                                        maybeUserProfileOfSignedInUser
                                                .map(UserProfile::getSubjectID)
                                                .orElse(null)))
                        .withRpPairwiseId(request.rpPairwiseId())
                        .build();

        var canReceiveEmailAddressResult =
                permissionDecisionManager.canReceiveEmailAddress(
                        JourneyType.REAUTHENTICATION, userPermissionContext);
        if (canReceiveEmailAddressResult.isFailure()) {
            DecisionError failure = canReceiveEmailAddressResult.getFailure();
            LOG.error("Failure to get canReceiveEmailAddress decision due to {}", failure);
            return DecisionErrorHttpMapper.toApiGatewayProxyErrorResponse(failure);
        }

        Decision canReceiveEmailAddressDecision = canReceiveEmailAddressResult.getSuccess();

        if (canReceiveEmailAddressDecision instanceof Decision.ReauthLockedOut reauthLockedOut) {
            ReauthFailureReasons failureReason =
                    ForbiddenReasonAntiCorruption.toReauthFailureReason(
                            reauthLockedOut.forbiddenReason());

            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                    auditContext,
                    ReauthMetadataBuilder.builder(request.rpPairwiseId())
                            .withAllIncorrectAttemptCounts(reauthLockedOut.detailedCounts())
                            .withFailureReason(failureReason)
                            .build());
            cloudwatchMetricsService.incrementCounter(
                    CloudwatchMetrics.REAUTH_FAILED.getValue(),
                    Map.of(
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment(),
                            FAILURE_REASON.getValue(),
                            failureReason == null ? "unknown" : failureReason.getValue()));

            LOG.warn("Account is unable to reauth due to too many failed attempts");
            return generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS);
        } else if (!(canReceiveEmailAddressDecision instanceof Decision.Permitted)) {
            return generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.UNHANDLED_NEGATIVE_DECISION);
        }

        if (!isTheUserSubmittedEmailAssociatedWithTheRpSubmittedPairwiseId) {
            LOG.warn(
                    "Could not calculate rp pairwise ID. User re-authentication verification failed");
            return generateErrorResponse(
                    maybeUserProfileOfSignedInUser,
                    request.rpPairwiseId(),
                    auditContext,
                    pairwiseIdMetadataPair,
                    request.email(),
                    maybeUserProfileOfUserSuppliedEmail);
        }

        auditService.submitAuditEvent(
                AUTH_REAUTH_ACCOUNT_IDENTIFIED,
                auditContext,
                pairwiseIdMetadataPair,
                pair(
                        "incorrect_email_attempt_count",
                        canReceiveEmailAddressDecision.attemptCount()));

        return generateSuccessResponse();
    }

    private APIGatewayProxyResponseEvent generateSuccessResponse() {
        LOG.info("Successfully processed CheckReAuthUser request");
        return generateApiGatewayProxyResponse(200, "");
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            Optional<UserProfile> userProfileOfSignedInUser,
            String rpPairwiseId,
            AuditContext auditContext,
            AuditService.MetadataPair pairwiseIdMetadataPair,
            String userSuppliedEmail,
            Optional<UserProfile> userProfileOfSuppliedEmail) {

        var userPermissionContext =
                UserPermissionContext.builder()
                        .withRpPairwiseId(rpPairwiseId)
                        .withInternalSubjectId(
                                userProfileOfSignedInUser
                                        .map(UserProfile::getSubjectID)
                                        .orElse(null))
                        .build();

        var trackingResult =
                userActionsManager.incorrectEmailAddressReceived(
                        JourneyType.REAUTHENTICATION, userPermissionContext);
        if (trackingResult.isFailure()) {
            TrackingError failure = trackingResult.getFailure();
            LOG.error("Failed to track incorrect email address: {}", failure);
            return TrackingErrorHttpMapper.toApiGatewayProxyErrorResponse(failure);
        }

        var canReceiveEmailAddressResult =
                permissionDecisionManager.canReceiveEmailAddress(
                        JourneyType.REAUTHENTICATION, userPermissionContext);
        if (canReceiveEmailAddressResult.isFailure()) {
            DecisionError failure = canReceiveEmailAddressResult.getFailure();
            LOG.error("Failure to get canReceiveEmailAddress decision due to {}", failure);
            return DecisionErrorHttpMapper.toApiGatewayProxyErrorResponse(failure);
        }

        Decision canReceiveEmailAddressDecision = canReceiveEmailAddressResult.getSuccess();

        var pairBuilder =
                ReauthMetadataBuilder.builder(rpPairwiseId)
                        .withIncorrectEmailCount(canReceiveEmailAddressDecision.attemptCount())
                        .withRestrictedUserSuppliedEmailPair(userSuppliedEmail);

        userProfileOfSuppliedEmail.ifPresent(
                userProfile ->
                        pairBuilder.withRestrictedUserIdForUserSuppliedEmailPair(
                                userProfile.getSubjectID()));

        auditService.submitAuditEvent(
                AUTH_REAUTH_INCORRECT_EMAIL_ENTERED, auditContext, pairBuilder.build());

        if (canReceiveEmailAddressDecision instanceof Decision.ReauthLockedOut reauthLockedOut) {
            ReauthFailureReasons failureReason =
                    ForbiddenReasonAntiCorruption.toReauthFailureReason(
                            reauthLockedOut.forbiddenReason());

            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                    auditContext,
                    ReauthMetadataBuilder.builder(rpPairwiseId)
                            .withAllIncorrectAttemptCounts(reauthLockedOut.detailedCounts())
                            .withFailureReason(failureReason)
                            .build());
            cloudwatchMetricsService.incrementCounter(
                    CloudwatchMetrics.REAUTH_FAILED.getValue(),
                    Map.of(
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment(),
                            FAILURE_REASON.getValue(),
                            failureReason.getValue()));

            auditService.submitAuditEvent(
                    AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED,
                    auditContext,
                    pair(
                            AUDIT_EVENT_EXTENSIONS_ATTEMPT_NO_FAILED_AT,
                            configurationService.getMaxEmailReAuthRetries()),
                    pairwiseIdMetadataPair);

            LOG.warn("Account is unable to reauth due to too many failed attempts");
            return generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS);
        } else if (!(canReceiveEmailAddressDecision instanceof Decision.Permitted)) {
            return generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.UNHANDLED_NEGATIVE_DECISION);
        }

        return generateApiGatewayProxyErrorResponse(404, USER_NOT_FOUND);
    }
}
