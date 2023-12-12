package uk.gov.di.orchestration.audit;

import uk.gov.di.orchestration.shared.services.AuditService;

import java.util.Objects;

public final class AuditContext {
    private String clientSessionId;
    private String sessionId;
    private String clientId;
    private String subjectId;
    private String email;
    private String ipAddress;
    private String phoneNumber;
    private String persistentSessionId;
    private AuditService.MetadataPair[] metadataPairs;

    public AuditContext(
            String clientSessionId,
            String sessionId,
            String clientId,
            String subjectId,
            String email,
            String ipAddress,
            String phoneNumber,
            String persistentSessionId,
            AuditService.MetadataPair... metadataPairs) {
        this.clientSessionId = clientSessionId;
        this.sessionId = sessionId;
        this.clientId = clientId;
        this.subjectId = subjectId;
        this.email = email;
        this.ipAddress = ipAddress;
        this.phoneNumber = phoneNumber;
        this.persistentSessionId = persistentSessionId;
        this.metadataPairs = metadataPairs;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public void setClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getSubjectId() {
        return subjectId;
    }

    public void setSubjectId(String subjectId) {
        this.subjectId = subjectId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getPersistentSessionId() {
        return persistentSessionId;
    }

    public void setPersistentSessionId(String persistentSessionId) {
        this.persistentSessionId = persistentSessionId;
    }

    public AuditService.MetadataPair[] getMetadataPairs() {
        return metadataPairs;
    }

    public void setMetadataPairs(AuditService.MetadataPair[] metadataPairs) {
        this.metadataPairs = metadataPairs;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (AuditContext) obj;
        return Objects.equals(this.clientSessionId, that.clientSessionId)
                && Objects.equals(this.sessionId, that.sessionId)
                && Objects.equals(this.clientId, that.clientId)
                && Objects.equals(this.subjectId, that.subjectId)
                && Objects.equals(this.email, that.email)
                && Objects.equals(this.ipAddress, that.ipAddress)
                && Objects.equals(this.phoneNumber, that.phoneNumber)
                && Objects.equals(this.persistentSessionId, that.persistentSessionId)
                && Objects.equals(this.metadataPairs, that.metadataPairs);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                clientSessionId,
                sessionId,
                clientId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                metadataPairs);
    }

    @Override
    public String toString() {
        return "AuditContext["
                + "clientSessionId="
                + clientSessionId
                + ", "
                + "sessionId="
                + sessionId
                + ", "
                + "clientId="
                + clientId
                + ", "
                + "subjectId="
                + subjectId
                + ", "
                + "email="
                + email
                + ", "
                + "ipAddress="
                + ipAddress
                + ", "
                + "phoneNumber="
                + phoneNumber
                + ", "
                + "persistentSessionId="
                + persistentSessionId
                + ", "
                + "metadataPairs="
                + metadataPairs
                + ']';
    }
}
