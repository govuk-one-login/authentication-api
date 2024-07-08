package uk.gov.di.authentication.frontendapi.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public abstract class MfaCodeProcessor {
    protected final Logger LOG = LogManager.getLogger(this.getClass());
    public final CodeStorageService codeStorageService;
    public final DynamoAccountModifiersService accountModifiersService;
    private final int maxRetries;
    public final String emailAddress;
    private final UserContext userContext;
    protected final AuthenticationService dynamoService;
    protected final AuditService auditService;

    MfaCodeProcessor(
            UserContext userContext,
            CodeStorageService codeStorageService,
            int maxRetries,
            AuthenticationService dynamoService,
            AuditService auditService,
            DynamoAccountModifiersService accountModifiersService) {
        this.emailAddress = userContext.getSession().getEmailAddress();
        this.userContext = userContext;
        this.codeStorageService = codeStorageService;
        this.maxRetries = maxRetries;
        this.dynamoService = dynamoService;
        this.auditService = auditService;
        this.accountModifiersService = accountModifiersService;
    }

    boolean isCodeBlockedForSession(String codeBlockedKeyPrefix) {
        return codeStorageService.isBlockedForEmail(emailAddress, codeBlockedKeyPrefix);
    }

    boolean hasExceededRetryLimit(MFAMethodType mfaMethodType) {
        LOG.info("Max retries: {}", maxRetries);
        return codeStorageService.getIncorrectMfaCodeAttemptsCount(emailAddress, mfaMethodType)
                > maxRetries;
    }

    void incrementRetryCount(MFAMethodType mfaMethodType) {
        codeStorageService.increaseIncorrectMfaCodeAttemptsCount(emailAddress, mfaMethodType);
    }

    void resetCodeIncorrectEntryCount(MFAMethodType mfaMethodType) {
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(emailAddress, mfaMethodType);
    }

    void submitAuditEvent(
            AuditableEvent auditableEvent,
            MFAMethodType mfaMethodType,
            String phoneNumber,
            String ipAddress,
            String persistentSessionId,
            boolean accountRecovery) {

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getSession().getInternalCommonSubjectIdentifier(),
                        emailAddress,
                        ipAddress,
                        phoneNumber,
                        persistentSessionId);

        auditService.submitAuditEvent(
                auditableEvent,
                auditContext,
                pair("mfa-type", mfaMethodType.getValue()),
                pair("account-recovery", accountRecovery));
    }

    void clearAccountRecoveryBlockIfPresent(
            MFAMethodType mfaMethodType, String ipAddress, String persistentSessionId) {
        var accountRecoveryBlockPresent =
                accountModifiersService.isAccountRecoveryBlockPresent(
                        userContext.getSession().getInternalCommonSubjectIdentifier());
        if (accountRecoveryBlockPresent) {
            LOG.info("AccountRecovery block is present. Removing block");
            accountModifiersService.removeAccountRecoveryBlockIfPresent(
                    userContext.getSession().getInternalCommonSubjectIdentifier());
            var auditContext =
                    auditContextFromUserContext(
                            userContext,
                            userContext.getSession().getInternalCommonSubjectIdentifier(),
                            emailAddress,
                            ipAddress,
                            AuditService.UNKNOWN,
                            persistentSessionId);
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.ACCOUNT_RECOVERY_BLOCK_REMOVED,
                    auditContext,
                    pair("mfa-type", mfaMethodType.getValue()));
        }
    }

    public abstract Optional<ErrorResponse> validateCode();

    public abstract void processSuccessfulCodeRequest(String ipAddress, String persistentSessionId);
}
