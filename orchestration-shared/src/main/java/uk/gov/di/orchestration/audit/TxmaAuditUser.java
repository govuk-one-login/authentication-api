package uk.gov.di.orchestration.audit;

import com.google.gson.annotations.Expose;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

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

        return new EqualsBuilder()
                .append(userId, that.userId)
                .append(transactionId, that.transactionId)
                .append(email, that.email)
                .append(phone, that.phone)
                .append(ipAddress, that.ipAddress)
                .append(sessionId, that.sessionId)
                .append(persistentSessionId, that.persistentSessionId)
                .append(govukSigninJourneyId, that.govukSigninJourneyId)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(userId)
                .append(transactionId)
                .append(email)
                .append(phone)
                .append(ipAddress)
                .append(sessionId)
                .append(persistentSessionId)
                .append(govukSigninJourneyId)
                .toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("userId", userId)
                .append("transactionId", transactionId)
                .append("email", email)
                .append("phone", phone)
                .append("ipAddress", ipAddress)
                .append("sessionId", sessionId)
                .append("persistentSessionId", persistentSessionId)
                .append("govukSigninJourneyId", govukSigninJourneyId)
                .toString();
    }
}
