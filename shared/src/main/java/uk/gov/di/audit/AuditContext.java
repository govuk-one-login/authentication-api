package uk.gov.di.audit;

import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.state.UserContext;

public record AuditContext(
        String clientId,
        String clientSessionId,
        String sessionId,
        String subjectId,
        String email,
        String ipAddress,
        String phoneNumber,
        String persistentSessionId,
        String txmaAuditEncoded,
        Integer passkeyCount) {

    public AuditContext(
            String clientId,
            String clientSessionId,
            String sessionId,
            String subjectId,
            String email,
            String ipAddress,
            String phoneNumber,
            String persistentSessionId,
            String txmaAuditEncoded) {
        this(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded,
                null);
    }

    public static AuditContext auditContextFromUserContext(
            UserContext userContext,
            String subjectId,
            String email,
            String ipAddress,
            String phoneNumber,
            String persistentSessionId) {
        return new AuditContext(
                userContext.getAuthSession().getClientId(),
                userContext.getClientSessionId(),
                userContext.getAuthSession().getSessionId(),
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                userContext.getTxmaAuditEncoded());
    }

    public static AuditContext emptyAuditContext() {
        return new AuditContext(
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN);
    }

    public AuditContext withPhoneNumber(String phoneNumber) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withUserId(String subjectId) {
        return withSubjectId(subjectId);
    }

    public AuditContext withTxmaAuditEncoded(String txmaAuditEncoded) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withSubjectId(String subjectId) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withEmail(String email) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withIpAddress(String ipAddress) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withClientId(String clientId) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withClientSessionId(String clientSessionId) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withSessionId(String sessionId) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withPersistentSessionId(String persistentSessionId) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withPasskeyCount(Integer passkeyCount) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded,
                passkeyCount);
    }
}
