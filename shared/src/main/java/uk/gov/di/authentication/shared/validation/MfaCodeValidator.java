package uk.gov.di.authentication.shared.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public abstract class MfaCodeValidator {
    protected Logger LOG = LogManager.getLogger(this.getClass());
    private final CodeStorageService codeStorageService;
    private final Session session;
    private final MFAMethodType mfaMethodType;
    private final int maxRetries;
    private final boolean isTestClientEnabled;
    private final DynamoService dynamoService;

    MfaCodeValidator(
            MFAMethodType mfaMethodType,
            UserContext userContext,
            CodeStorageService codeStorageService,
            ConfigurationService configurationService,
            DynamoService dynamoService,
            int maxRetries) {
        this.mfaMethodType = mfaMethodType;
        this.session = userContext.getSession();
        this.codeStorageService = codeStorageService;
        this.maxRetries = maxRetries;
        this.isTestClientEnabled = configurationService.isTestClientsEnabled();
        this.dynamoService = dynamoService;
    }

    boolean isCodeBlockedForSession() {
        return codeStorageService.isBlockedForEmail(
                session.getEmailAddress(), CODE_BLOCKED_KEY_PREFIX);
    }

    boolean hasExceededRetryLimit() {
        LOG.info("Session retry count: {}", session.getRetryCount());
        LOG.info("Max retries: {}", maxRetries);
        return session.getRetryCount() > maxRetries;
    }

    void incrementRetryCount() {
        session.incrementRetryCount();
    }

    void resetCodeRequestCount() {
        session.resetRetryCount();
    }

    public abstract Optional<ErrorResponse> validateCode(String code);
}
