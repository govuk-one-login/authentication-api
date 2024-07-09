package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import uk.gov.di.accountmanagement.services.AccountDeletionService;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.DynamoDeleteService;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Optional;

public class ManuallyDeleteAccountHandler implements RequestHandler<String, String> {
    private final AuthenticationService authenticationService;
    private final AccountDeletionService accountDeletionService;

    public ManuallyDeleteAccountHandler(
            AuthenticationService authenticationService,
            AccountDeletionService accountDeletionService) {
        this.authenticationService = authenticationService;
        this.accountDeletionService = accountDeletionService;
    }

    public ManuallyDeleteAccountHandler(ConfigurationService configurationService) {
        this.authenticationService = new DynamoService(configurationService);
        var sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        var auditService = new AuditService(configurationService);
        var dynamoDeleteService = new DynamoDeleteService(configurationService);
        this.accountDeletionService =
                new AccountDeletionService(
                        authenticationService,
                        sqsClient,
                        auditService,
                        configurationService,
                        dynamoDeleteService);
    }

    public ManuallyDeleteAccountHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public String handleRequest(String userEmail, Context context) {
        var userProfile =
                authenticationService
                        .getUserProfileByEmailMaybe(userEmail)
                        .orElseThrow(() -> new RuntimeException("User not found with given email"));

        try {
            var userIdentifiers =
                    accountDeletionService.removeAccount(
                            Optional.empty(), userProfile, Optional.empty());
            return userIdentifiers.toString();
        } catch (Json.JsonException e) {
            throw new RuntimeException(e);
        }
    }
}
