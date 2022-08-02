package uk.gov.di.audit;

import com.google.gson.annotations.Expose;

public class TxmaAuditUser {

    @Expose private String userId;
    @Expose private String transactionId;
    @Expose private String email;
    @Expose private String phone;
    @Expose private String ipAddress;
    @Expose private String sessionId;
    @Expose private String persistentSessionId;
    @Expose private String govukSigninJourneyId;

    public static TxmaAuditUser user() {
        return new TxmaAuditUser();
    }

    public TxmaAuditUser withUserId(String userId) {
        this.userId = userId;
        return this;
    }

    public TxmaAuditUser withTransactionId(String transactionId) {
        this.transactionId = transactionId;
        return this;
    }

    public TxmaAuditUser withEmail(String email) {
        this.email = email;
        return this;
    }

    public TxmaAuditUser withPhone(String phone) {
        this.phone = phone;
        return this;
    }

    public TxmaAuditUser withIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
        return this;
    }

    public TxmaAuditUser withSessionId(String sessionId) {
        this.sessionId = sessionId;
        return this;
    }

    public TxmaAuditUser withPersistentSessionId(String persistentSessionId) {
        this.persistentSessionId = persistentSessionId;
        return this;
    }

    public TxmaAuditUser withGovukSigninJourneyId(String govukSigninJourneyId) {
        this.govukSigninJourneyId = govukSigninJourneyId;
        return this;
    }
}
