package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.entity.InactiveAccountDeletionMessage;
import uk.gov.di.accountmanagement.exceptions.RecentlyActiveAccountException;
import uk.gov.di.accountmanagement.services.AccountDeletionService;
import uk.gov.di.accountmanagement.services.IADCircuitBreakerService;
import uk.gov.di.accountmanagement.services.InactiveAccountDeletionTokenService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.AuthDeleteAccount;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.InactiveAccountFailsafeCheckHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AccountDataApiService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.GUARDRAIL_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.GUARDRAIL_PREVENTED_INACTIVE_ACCOUNT_DELETION;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class InactiveAccountDeletionHandler implements RequestHandler<SQSEvent, SQSBatchResponse> {

    private static final Logger LOG = LogManager.getLogger(InactiveAccountDeletionHandler.class);
    private static final String GUARDRAIL_TYPE_VALUE = "AuthUserActivityCheck";

    private final Json objectMapper = SerializationService.getInstance();
    private final InactiveAccountDeletionTokenService tokenService;
    private final AccountDeletionService accountDeletionService;
    private final DynamoService dynamoService;
    private final StructuredAuditService structuredAuditService;
    private final ConfigurationService configurationService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final IADCircuitBreakerService iadCircuitBreakerService;
    private final Clock clock;

    public InactiveAccountDeletionHandler() {
        this(ConfigurationService.getInstance());
    }

    public InactiveAccountDeletionHandler(ConfigurationService configurationService) {
        this.tokenService = new InactiveAccountDeletionTokenService(configurationService);
        var accountDataApiService = new AccountDataApiService(configurationService);
        this.accountDeletionService =
                new AccountDeletionService(
                        null, null, null, configurationService, null, accountDataApiService);
        this.dynamoService = new DynamoService(configurationService);
        this.structuredAuditService = new StructuredAuditService(configurationService);
        this.configurationService = configurationService;
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.iadCircuitBreakerService =
                new IADCircuitBreakerService(configurationService.getIADCircuitBreakerTableName());
        this.clock = Clock.systemUTC();
    }

    public InactiveAccountDeletionHandler(
            InactiveAccountDeletionTokenService tokenService,
            AccountDeletionService accountDeletionService,
            DynamoService dynamoService,
            StructuredAuditService structuredAuditService,
            ConfigurationService configurationService,
            CloudwatchMetricsService cloudwatchMetricsService,
            IADCircuitBreakerService iadCircuitBreakerService,
            Clock clock) {
        this.tokenService = tokenService;
        this.accountDeletionService = accountDeletionService;
        this.dynamoService = dynamoService;
        this.structuredAuditService = structuredAuditService;
        this.configurationService = configurationService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.iadCircuitBreakerService = iadCircuitBreakerService;
        this.clock = clock;
    }

    @Override
    public SQSBatchResponse handleRequest(SQSEvent event, Context context) {
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> processMessages(event));
    }

    public SQSBatchResponse processMessages(SQSEvent event) {
        attachTraceId();

        var failures = new ArrayList<SQSBatchResponse.BatchItemFailure>();

        if (event == null || event.getRecords() == null) {
            LOG.warn("Received null event or null records");
            return new SQSBatchResponse(failures);
        }

        LOG.info("Processing inactive account deletion batch, size: {}", event.getRecords().size());

        for (SQSMessage msg : event.getRecords()) {
            try {
                LOG.info("Picked up SQS message with ID: {}", msg.getMessageId());
                if (iadCircuitBreakerService.isCircuitBreakerTripped()) {
                    failRemainingMessages(event, msg, failures);
                    break;
                }
                processAccountDeletion(msg);
            } catch (RecentlyActiveAccountException e) {
                LOG.warn(
                        "Adding SQS message with ID: {} to failures due to recent account activity. {}",
                        msg.getMessageId(),
                        e.getMessage());
                failures.add(new SQSBatchResponse.BatchItemFailure(msg.getMessageId()));
            } catch (Exception e) {
                LOG.error(
                        "Failed to process inactive account deletion message with id: {}",
                        msg.getMessageId(),
                        e);
                failures.add(new SQSBatchResponse.BatchItemFailure(msg.getMessageId()));
            }
        }

        LOG.info(
                "Completed batch processing. Failures: {}/{}",
                failures.size(),
                event.getRecords().size());
        return new SQSBatchResponse(failures);
    }

    private void processAccountDeletion(SQSMessage msg) throws JsonException {
        var message = parseMessage(msg);
        var publicSubjectId = message.publicSubjectId();
        LOG.info("Processing inactive account deletion for publicSubjectId: {}", publicSubjectId);

        var maybeUserProfile = getUserProfile(publicSubjectId);
        if (maybeUserProfile.isEmpty()) {
            LOG.warn(
                    "User profile not found for publicSubjectId: {}. Account may have already been deleted. Skipping.",
                    publicSubjectId);
            return;
        }
        var userProfile = maybeUserProfile.get();

        var userCredentials = getUserCredentials(userProfile.getEmail());

        var activityCheck =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, clock);
        if (activityCheck.recentlyActive()) {
            emitGuardrailMetric();
            tripCircuitBreaker(publicSubjectId);
            throw new RecentlyActiveAccountException(
                    String.format(
                            "Skipping deletion for publicSubjectId: %s. Account has recent activity on attribute: %s",
                            publicSubjectId, activityCheck.triggeringAttribute()));
        }

        deleteAccount(publicSubjectId);
        emitAuditEvent(userProfile);
    }

    private Optional<UserProfile> getUserProfile(String publicSubjectId) {
        return dynamoService.getOptionalUserProfileFromPublicSubject(publicSubjectId);
    }

    private UserCredentials getUserCredentials(String email) {
        var userCredentials = dynamoService.getUserCredentialsFromEmail(email);
        if (userCredentials == null) {
            LOG.info(
                    "User credentials not found for email. Proceeding with user profile fields only.");
        }
        return userCredentials;
    }

    private void deleteAccount(String publicSubjectId) {
        var tokenResult = tokenService.createAccountDataApiAccessToken(publicSubjectId);
        if (tokenResult.isFailure()) {
            throw new RuntimeException(
                    "Failed to mint account-delete token for publicSubjectId: " + publicSubjectId);
        }
        var token = tokenResult.getSuccess().getValue();

        accountDeletionService.deleteAccountViaDataApi(publicSubjectId, token);
    }

    private void emitAuditEvent(UserProfile userProfile) {
        try {
            var internalCommonSubjectIdentifier =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userProfile,
                            configurationService.getInternalSectorUri(),
                            dynamoService);
            var auditContext =
                    new AuditContext(
                            StructuredAuditService.UNKNOWN,
                            StructuredAuditService.UNKNOWN,
                            StructuredAuditService.UNKNOWN,
                            internalCommonSubjectIdentifier.getValue(),
                            userProfile.getEmail(),
                            StructuredAuditService.UNKNOWN,
                            userProfile.getPhoneNumber(),
                            StructuredAuditService.UNKNOWN,
                            StructuredAuditService.UNKNOWN);
            var auditEvent =
                    AuthDeleteAccount.create(
                            auditContext,
                            userProfile.getPublicSubjectID(),
                            userProfile.getLegacySubjectID(),
                            AccountDeletionReason.INACTIVE_ACCOUNT.name(),
                            Clock.systemUTC());
            structuredAuditService.submitAuditEvent(auditEvent);
        } catch (Exception e) {
            LOG.error(
                    "Failed to submit AUTH_DELETE_ACCOUNT audit event for publicSubjectId: {}",
                    userProfile.getPublicSubjectID(),
                    e);
        }
    }

    private void emitGuardrailMetric() {
        try {
            cloudwatchMetricsService.incrementCounter(
                    GUARDRAIL_PREVENTED_INACTIVE_ACCOUNT_DELETION.getValue(),
                    Map.of(
                            GUARDRAIL_TYPE.getValue(),
                            GUARDRAIL_TYPE_VALUE,
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment()));
        } catch (Exception e) {
            LOG.error("Failed to emit guardrail hit metric", e);
        }
    }

    private void tripCircuitBreaker(String publicSubjectId) {
        try {
            iadCircuitBreakerService.tripCircuitBreaker(GUARDRAIL_TYPE_VALUE, publicSubjectId);
        } catch (Exception e) {
            LOG.error(
                    "Failed to trip IAD circuit breaker for publicSubjectId: {}",
                    publicSubjectId,
                    e);
        }
    }

    private void failRemainingMessages(
            SQSEvent event,
            SQSMessage currentMsg,
            List<SQSBatchResponse.BatchItemFailure> failures) {
        var records = event.getRecords();
        var startIndex = records.indexOf(currentMsg);
        var remainingCount = records.size() - startIndex;

        LOG.warn(
                "IAD circuit breaker is tripped. Aborting processing. Reporting current and remaining {} messages as batch item failures.",
                remainingCount);

        for (int i = startIndex; i < records.size(); i++) {
            LOG.warn(
                    "Adding SQS message with ID: {} to failures due to the circuit breaker being tripped.",
                    records.get(i).getMessageId());
            failures.add(new SQSBatchResponse.BatchItemFailure(records.get(i).getMessageId()));
        }
    }

    private InactiveAccountDeletionMessage parseMessage(SQSMessage msg) throws JsonException {
        var message = objectMapper.readValue(msg.getBody(), InactiveAccountDeletionMessage.class);
        if (message.publicSubjectId() == null || message.publicSubjectId().isBlank()) {
            throw new IllegalArgumentException(
                    "publicSubjectId is missing or blank in message: " + msg.getMessageId());
        }
        return message;
    }
}
