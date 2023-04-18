package uk.gov.di.authentication.shared.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
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

    boolean isCodeBlockedForSession(MFAMethodType mfaMethodType) {
        // TODO: This is a transitional measure; code block has been applied once for all MFA types
        // but will now be differentiated per MFA type; existing blocks should still be valid in
        // cache, however, hence checking both conditions. Once the old cache values expire (15
        // minutes), only the composite prefix will need to be checked
        return codeStorageService.isBlockedForEmail(
                        emailAddress, CODE_BLOCKED_KEY_PREFIX + mfaMethodType)
                || codeStorageService.isBlockedForEmail(emailAddress, CODE_BLOCKED_KEY_PREFIX);
    }

    boolean hasExceededRetryLimit(MFAMethodType mfaMethodType) {
        LOG.info("Max retries: {}", maxRetries);
        return codeStorageService.getIncorrectMfaCodeAttemptsCount(emailAddress, mfaMethodType)
                > maxRetries;
    }

    void incrementRetryCount(MFAMethodType mfaMethodType) {
        codeStorageService.increaseIncorrectMfaCodeAttemptsCount(emailAddress, mfaMethodType);
    }

    void resetCodeRequestCount(MFAMethodType mfaMethodType) {
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(emailAddress);
    }

    public abstract Optional<ErrorResponse> validateCode(String code);
}
