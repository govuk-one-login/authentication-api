package uk.gov.di.audit;

import com.google.gson.annotations.Expose;

import java.util.Objects;

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

    public String getPhone() {
        return phone;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TxmaAuditUser that = (TxmaAuditUser) o;
        return Objects.equals(userId, that.userId)
                && Objects.equals(transactionId, that.transactionId)
                && Objects.equals(email, that.email)
                && Objects.equals(phone, that.phone)
                && Objects.equals(ipAddress, that.ipAddress)
                && Objects.equals(sessionId, that.sessionId)
                && Objects.equals(persistentSessionId, that.persistentSessionId)
                && Objects.equals(govukSigninJourneyId, that.govukSigninJourneyId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
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
