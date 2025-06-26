package uk.gov.di.authentication.frontendapi.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
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
    protected final AuthenticationService authenticationService;
    protected final AuditService auditService;
    protected final MFAMethodsService mfaMethodsService;

    MfaCodeProcessor(
            UserContext userContext,
            CodeStorageService codeStorageService,
            int maxRetries,
            AuthenticationService authenticationService,
            AuditService auditService,
            DynamoAccountModifiersService accountModifiersService,
            MFAMethodsService mfaMethodsService) {
        this.emailAddress = userContext.getAuthSession().getEmailAddress();
        this.userContext = userContext;
        this.codeStorageService = codeStorageService;
        this.maxRetries = maxRetries;
        this.authenticationService = authenticationService;
        this.auditService = auditService;
        this.accountModifiersService = accountModifiersService;
        this.mfaMethodsService = mfaMethodsService;
    }

    boolean isCodeBlockedForSession(String codeBlockedKeyPrefix) {
        return codeStorageService.isBlockedForEmail(emailAddress, codeBlockedKeyPrefix);
    }

    boolean hasExceededRetryLimit() {
        LOG.info("Max retries: {}", maxRetries);
        return codeStorageService.getIncorrectMfaCodeAttemptsCount(emailAddress) >= maxRetries;
    }

    void incrementRetryCount() {
        codeStorageService.increaseIncorrectMfaCodeAttemptsCount(emailAddress);
    }

    void resetCodeIncorrectEntryCount() {
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(emailAddress);
    }

    void submitAuditEvent(
            AuditableEvent auditableEvent,
            MFAMethodType mfaMethodType,
            String phoneNumber,
            String ipAddress,
            String persistentSessionId,
            boolean accountRecovery,
            AuditService.MetadataPair... metadataPairs) {

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        emailAddress,
                        ipAddress,
                        phoneNumber,
                        persistentSessionId);

        var allPairs = new AuditService.MetadataPair[2 + metadataPairs.length];
        allPairs[0] = pair("mfa-type", mfaMethodType.getValue());
        allPairs[1] = pair("account-recovery", accountRecovery);
        System.arraycopy(metadataPairs, 0, allPairs, 2, metadataPairs.length);

        auditService.submitAuditEvent(auditableEvent, auditContext, allPairs);
    }

    void clearAccountRecoveryBlockIfPresent(
            MFAMethodType mfaMethodType, String ipAddress, String persistentSessionId) {
        var accountRecoveryBlockPresent =
                accountModifiersService.isAccountRecoveryBlockPresent(
                        userContext.getAuthSession().getInternalCommonSubjectId());
        if (accountRecoveryBlockPresent) {
            LOG.info("AccountRecovery block is present. Removing block");
            accountModifiersService.removeAccountRecoveryBlockIfPresent(
                    userContext.getAuthSession().getInternalCommonSubjectId());
            var auditContext =
                    auditContextFromUserContext(
                            userContext,
                            userContext.getAuthSession().getInternalCommonSubjectId(),
                            emailAddress,
                            ipAddress,
                            AuditService.UNKNOWN,
                            persistentSessionId);
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_BLOCK_REMOVED,
                    auditContext,
                    pair("mfa-type", mfaMethodType.getValue()));
        }
    }

    public abstract Optional<ErrorResponse> validateCode();

    public abstract void processSuccessfulCodeRequest(
            String ipAddress, String persistentSessionId, UserProfile userProfile);
}
