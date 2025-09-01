package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.entity.BulkUserDeleteRequest;
import uk.gov.di.accountmanagement.services.AccountDeletionService;
import uk.gov.di.accountmanagement.services.AwsSnsClient;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.DynamoDeleteService;
import uk.gov.di.accountmanagement.services.ManualAccountDeletionService;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class BulkRemoveAccountHandler implements RequestHandler<BulkUserDeleteRequest, String> {
    private static final Logger LOG = LogManager.getLogger(BulkRemoveAccountHandler.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final int BATCH_SIZE = 50;

    private final AuthenticationService authenticationService;
    private final ManualAccountDeletionService manualAccountDeletionService;

    public BulkRemoveAccountHandler(
            AuthenticationService authenticationService,
            ManualAccountDeletionService manualAccountDeletionService) {
        this.authenticationService = authenticationService;
        this.manualAccountDeletionService = manualAccountDeletionService;
    }

    public BulkRemoveAccountHandler(ConfigurationService configurationService) {
        this.authenticationService = new DynamoService(configurationService);
        var emailSqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        var legacyAccountDeletionSnsClient =
                new AwsSnsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getLegacyAccountDeletionTopicArn(),
                        configurationService.getSnsEndpointUri());
        var auditService = new AuditService(configurationService);
        var dynamoDeleteService = new DynamoDeleteService(configurationService);
        var accountDeletionService =
                new AccountDeletionService(
                        authenticationService,
                        emailSqsClient,
                        auditService,
                        configurationService,
                        dynamoDeleteService);
        this.manualAccountDeletionService =
                new ManualAccountDeletionService(
                        accountDeletionService,
                        legacyAccountDeletionSnsClient,
                        configurationService);
    }

    public BulkRemoveAccountHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public String handleRequest(BulkUserDeleteRequest request, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());

        try {
            LOG.info("BulkRemoveAccountHandler received request");

            validateRequest(request);

            String reference = request.reference();
            LOG.info("Processing bulk deletion request with reference: {}", reference);

            List<String> emailsToProcess = new ArrayList<>(request.emails());
            List<String> processedEmails = new ArrayList<>();
            List<String> failedEmails = new ArrayList<>();
            List<String> notFoundEmails = new ArrayList<>();
            List<String> filteredOutEmails = new ArrayList<>();

            LOG.info(
                    "Processing {} emails for bulk deletion with reference: {}",
                    emailsToProcess.size(),
                    reference);

            while (!emailsToProcess.isEmpty()) {
                List<String> batch = new ArrayList<>();
                for (int i = 0; i < BATCH_SIZE && !emailsToProcess.isEmpty(); i++) {
                    batch.add(emailsToProcess.remove(0));
                }

                processBatch(
                        batch,
                        request,
                        reference,
                        processedEmails,
                        failedEmails,
                        notFoundEmails,
                        filteredOutEmails);
            }

            String result =
                    String.format(
                            "Bulk deletion completed for reference %s. Processed: %d, Failed: %d, Not found: %d, Filtered out: %d",
                            reference,
                            processedEmails.size(),
                            failedEmails.size(),
                            notFoundEmails.size(),
                            filteredOutEmails.size());

            LOG.info(result);
            return result;
        } catch (Exception e) {
            LOG.error("Unexpected error during bulk deletion", e);
            throw new RuntimeException("Bulk deletion failed", e);
        }
    }

    private static void validateRequest(BulkUserDeleteRequest request) {
        if (request.reference() == null || request.reference().trim().isEmpty()) {
            throw new IllegalArgumentException("Reference cannot be null or empty");
        }

        if (request.emails() == null || request.emails().isEmpty()) {
            throw new IllegalArgumentException("Email list cannot be null or empty");
        }

        if (request.createdAfter() == null) {
            throw new IllegalArgumentException("createdAfter cannot be null");
        }

        if (request.createdBefore() == null) {
            throw new IllegalArgumentException("createdBefore cannot be null");
        }
    }

    private void processBatch(
            List<String> batch,
            BulkUserDeleteRequest request,
            String reference,
            List<String> processedEmails,
            List<String> failedEmails,
            List<String> notFoundEmails,
            List<String> filteredOutEmails) {

        for (String email : batch) {
            try {
                String normalizedEmail = email.toLowerCase().trim();
                LOG.info("Processing deletion for email (reference: {})", reference);

                authenticationService
                        .getUserProfileByEmailMaybe(normalizedEmail)
                        .ifPresentOrElse(
                                userProfile -> {
                                    if (isWithinDateRange(userProfile, request)) {
                                        var accountIdentifiers =
                                                manualAccountDeletionService.manuallyDeleteAccount(
                                                        userProfile,
                                                        AccountDeletionReason
                                                                .BULK_SUPPORT_INITIATED,
                                                        false);
                                        LOG.info(
                                                "Successfully deleted account for email (reference: {}). Identifiers: {}",
                                                reference,
                                                accountIdentifiers);
                                        processedEmails.add(normalizedEmail);

                                    } else {
                                        LOG.info(
                                                "User filtered out - creation date outside specified range");
                                        filteredOutEmails.add(normalizedEmail);
                                    }
                                },
                                () -> {
                                    LOG.warn("User not found with email");
                                    notFoundEmails.add(normalizedEmail);
                                });
            } catch (Exception e) {
                LOG.error("Failed to delete account for email", e);
                failedEmails.add(email);
            }
        }
    }

    private boolean isWithinDateRange(UserProfile userProfile, BulkUserDeleteRequest request) {
        String createdDateStr = userProfile.getCreated();
        if (createdDateStr == null || createdDateStr.isEmpty()) {
            LOG.warn("User has no creation date, excluding from deletion");
            return false;
        }
        try {
            LocalDateTime createdDate = LocalDateTime.parse(createdDateStr, DATE_FORMATTER);
            return createdDate.isBefore(request.createdBefore())
                    && createdDate.isAfter(request.createdAfter());
        } catch (DateTimeParseException e) {
            LOG.warn("Invalid creation date format for user, excluding from deletion");
            return false;
        }
    }
}
