package uk.gov.di.orchestration.audit;

import com.google.gson.annotations.Expose;

public record TxmaAuditUser(
        @Expose String userId,
        @Expose String transactionId,
        @Expose String email,
        @Expose String phone,
        @Expose String ipAddress,
        @Expose String sessionId,
        @Expose String persistentSessionId,
        @Expose String govukSigninJourneyId) {

    public static TxmaAuditUser user() {
        return new TxmaAuditUser(null, null, null, null, null, null, null, null);
    }

    public TxmaAuditUser withUserId(String userId) {
        return new TxmaAuditUser(
                userId,
                transactionId,
                email,
                phone,
                ipAddress,
                sessionId,
                persistentSessionId,
                govukSigninJourneyId);
    }

    public TxmaAuditUser withTransactionId(String transactionId) {
        return new TxmaAuditUser(
                userId,
                transactionId,
                email,
                phone,
                ipAddress,
                sessionId,
                persistentSessionId,
                govukSigninJourneyId);
    }

    public TxmaAuditUser withEmail(String email) {
        return new TxmaAuditUser(
                userId,
                transactionId,
                email,
                phone,
                ipAddress,
                sessionId,
                persistentSessionId,
                govukSigninJourneyId);
    }

    public TxmaAuditUser withPhone(String phone) {
        return new TxmaAuditUser(
                userId,
                transactionId,
                email,
                phone,
                ipAddress,
                sessionId,
                persistentSessionId,
                govukSigninJourneyId);
    }

    public TxmaAuditUser withIpAddress(String ipAddress) {
        return new TxmaAuditUser(
                userId,
                transactionId,
                email,
                phone,
                ipAddress,
                sessionId,
                persistentSessionId,
                govukSigninJourneyId);
    }

    public TxmaAuditUser withSessionId(String sessionId) {
        return new TxmaAuditUser(
                userId,
                transactionId,
                email,
                phone,
                ipAddress,
                sessionId,
                persistentSessionId,
                govukSigninJourneyId);
    }

    public TxmaAuditUser withPersistentSessionId(String persistentSessionId) {
        return new TxmaAuditUser(
                userId,
                transactionId,
                email,
                phone,
                ipAddress,
                sessionId,
                persistentSessionId,
                govukSigninJourneyId);
    }

    public TxmaAuditUser withGovukSigninJourneyId(String govukSigninJourneyId) {
        return new TxmaAuditUser(
                userId,
                transactionId,
                email,
                phone,
                ipAddress,
                sessionId,
                persistentSessionId,
                govukSigninJourneyId);
    }
}
