package uk.gov.di.authentication.shared.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public abstract class MfaCodeValidator {
    protected final Logger LOG = LogManager.getLogger(this.getClass());
    private final CodeStorageService codeStorageService;
    private final Session session;
    private final int maxRetries;

    MfaCodeValidator(
            UserContext userContext, CodeStorageService codeStorageService, int maxRetries) {
        this.session = userContext.getSession();
        this.codeStorageService = codeStorageService;
        this.maxRetries = maxRetries;
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
