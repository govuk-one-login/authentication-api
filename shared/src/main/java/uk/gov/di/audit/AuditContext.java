package uk.gov.di.audit;

import uk.gov.di.authentication.shared.services.AuditService.MetadataPair;

import java.util.Arrays;
import java.util.Objects;

public class AuditContext {
    private String clientSessionId;
    private String sessionId;
    private String clientId;
    private String subjectId;
    private String email;
    private String ipAddress;
    private String phoneNumber;
    private String persistentSessionId;
    private MetadataPair[] metadataPairs = new MetadataPair[0];

    public AuditContext(
            String clientSessionId,
            String sessionId,
            String clientId,
            String subjectId,
            String email,
            String ipAddress,
            String phoneNumber,
            String persistentSessionId) {
        this.clientSessionId = clientSessionId;
        this.sessionId = sessionId;
        this.clientId = clientId;
        this.subjectId = subjectId;
        this.email = email;
        this.ipAddress = ipAddress;
        this.phoneNumber = phoneNumber;
        this.persistentSessionId = persistentSessionId;
    }

    public AuditContext(
            String clientSessionId,
            String sessionId,
            String clientId,
            String subjectId,
            String email,
            String ipAddress,
            String phoneNumber,
            String persistentSessionId,
            MetadataPair[] metadataPairs) {
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

    public MetadataPair[] getMetadataPairs() {
        return metadataPairs;
    }

    public void setMetadataPairs(MetadataPair[] metadataPairs) {
        this.metadataPairs = metadataPairs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditContext that = (AuditContext) o;
        return Objects.equals(clientSessionId, that.clientSessionId)
                && Objects.equals(sessionId, that.sessionId)
                && Objects.equals(clientId, that.clientId)
                && Objects.equals(subjectId, that.subjectId)
                && Objects.equals(email, that.email)
                && Objects.equals(ipAddress, that.ipAddress)
                && Objects.equals(phoneNumber, that.phoneNumber)
                && Objects.equals(persistentSessionId, that.persistentSessionId)
                && Arrays.equals(metadataPairs, that.metadataPairs);
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
                Arrays.hashCode(metadataPairs));
    }
}
