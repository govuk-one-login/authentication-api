package uk.gov.di.authentication.accountdata.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysRetrieveServiceFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

public class PasskeysRetrieveService {

    private static final Logger LOG = LogManager.getLogger(PasskeysRetrieveService.class);
    private final DynamoPasskeyService dynamoPasskeyService;
    private final ConfigurationService configurationService;

    public PasskeysRetrieveService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dynamoPasskeyService = new DynamoPasskeyService(configurationService);
    }

    public PasskeysRetrieveService(
            ConfigurationService configurationService, DynamoPasskeyService dynamoPasskeyService) {
        this.configurationService = configurationService;
        this.dynamoPasskeyService = dynamoPasskeyService;
    }

    public Result<PasskeysRetrieveServiceFailureReason, List<Passkey>> retrievePasskeys(
            String publicSubjectId) {
        if (publicSubjectId == null || publicSubjectId.isEmpty()) {
            LOG.error("Missing public subject id");
            return Result.failure(PasskeysRetrieveServiceFailureReason.MISSING_SUBJECT_ID);
        }

        try {
            var passkeysForUser = dynamoPasskeyService.getPasskeysForUser(publicSubjectId);
            return Result.success(passkeysForUser);
        } catch (Exception e) {
            LOG.error("Failed to retrieve passkeys", e);
            return Result.failure(PasskeysRetrieveServiceFailureReason.FAILED_TO_GET_PASSKEYS);
        }
    }
}
