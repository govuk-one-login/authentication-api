package uk.gov.di.audit;

import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

public record AuditContext(
        String clientId,
        String clientSessionId,
        String sessionId,
        String subjectId,
        String email,
        String ipAddress,
        String phoneNumber,
        String persistentSessionId,
        Optional<String> txmaAuditEncoded) {

    public static AuditContext auditContextFromUserContext(
            UserContext userContext,
            String subjectId,
            String email,
            String ipAddress,
            String phoneNumber,
            String persistentSessionId) {
        return new AuditContext(
                userContext.getClientId(),
                userContext.getClientSessionId(),
                userContext.getAuthSession().getSessionId(),
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                Optional.ofNullable(userContext.getTxmaAuditEncoded()));
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
                Optional.empty());
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

    public AuditContext withTxmaAuditEncoded(Optional<String> txmaAuditEncoded) {
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
}
