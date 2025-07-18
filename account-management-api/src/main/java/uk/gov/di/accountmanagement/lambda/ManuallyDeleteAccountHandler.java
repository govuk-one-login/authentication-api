package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.services.AccountDeletionService;
import uk.gov.di.accountmanagement.services.AwsSnsClient;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.DynamoDeleteService;
import uk.gov.di.accountmanagement.services.ManualAccountDeletionService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class ManuallyDeleteAccountHandler implements RequestHandler<String, String> {
    private final AuthenticationService authenticationService;
    private final ManualAccountDeletionService manualAccountDeletionService;

    public ManuallyDeleteAccountHandler(
            AuthenticationService authenticationService,
            ManualAccountDeletionService manualAccountDeletionService) {
        this.authenticationService = authenticationService;
        this.manualAccountDeletionService = manualAccountDeletionService;
    }

    public ManuallyDeleteAccountHandler(ConfigurationService configurationService) {
        this.authenticationService = new DynamoService(configurationService);
        var emailSqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        var legacyAccountDeletionSnsClient =
                new AwsSnsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getLegacyAccountDeletionTopicArn());
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

    public ManuallyDeleteAccountHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public String handleRequest(String rawUserEmail, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        var userEmail = rawUserEmail.toLowerCase().trim();
        var userProfile =
                authenticationService
                        .getUserProfileByEmailMaybe(userEmail)
                        .orElseThrow(() -> new RuntimeException("User not found with given email"));
        var accountIdentifiers = manualAccountDeletionService.manuallyDeleteAccount(userProfile);
        return accountIdentifiers.toString();
    }
}
