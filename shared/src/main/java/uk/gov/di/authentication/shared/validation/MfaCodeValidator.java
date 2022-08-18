package uk.gov.di.authentication.shared.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.CodeStorageService;

import java.util.Optional;

import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public abstract class MfaCodeValidator {
    protected final Logger LOG = LogManager.getLogger(this.getClass());
    private final CodeStorageService codeStorageService;
    private final int maxRetries;
    private final String emailAddress;

    MfaCodeValidator(String emailAddress, CodeStorageService codeStorageService, int maxRetries) {
        this.emailAddress = emailAddress;
        this.codeStorageService = codeStorageService;
        this.maxRetries = maxRetries;
    }

    boolean isCodeBlockedForSession() {
        return codeStorageService.isBlockedForEmail(emailAddress, CODE_BLOCKED_KEY_PREFIX);
    }

    boolean hasExceededRetryLimit() {
        LOG.info("Max retries: {}", maxRetries);
        return codeStorageService.getIncorrectMfaCodeAttemptsCount(emailAddress) > maxRetries;
    }

    void incrementRetryCount() {
        codeStorageService.increaseIncorrectMfaCodeAttemptsCount(emailAddress);
    }

    void resetCodeRequestCount() {
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(emailAddress);
    }

    public abstract Optional<ErrorResponse> validateCode(String code);
}
