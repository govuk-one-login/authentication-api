package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;

import java.util.ArrayList;
import java.util.List;

public class Session {

    public enum AccountState {
        NEW,
        EXISTING,
        UNKNOWN
    }

    @Expose private String sessionId;

    @Expose private List<String> clientSessions;

    @Expose private String emailAddress;

    @Expose private int retryCount;

    @Expose private int passwordResetCount;

    @Expose private int codeRequestCount;

    @Expose private CredentialTrustLevel currentCredentialStrength;

    @Expose private AccountState isNewAccount;

    @Expose private boolean authenticated;

    @Expose private int processingIdentityAttempts;

    public Session(String sessionId) {
        this.sessionId = sessionId;
        this.clientSessions = new ArrayList<>();
        this.isNewAccount = AccountState.UNKNOWN;
        this.processingIdentityAttempts = 0;
    }

    public Session(String sessionId, List<String> clientSessions, String emailAddress) {
        this.sessionId = sessionId;
        this.clientSessions = clientSessions;
        this.emailAddress = emailAddress;
        this.isNewAccount = AccountState.UNKNOWN;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public List<String> getClientSessions() {
        return clientSessions;
    }

    public Session addClientSession(String clientSessionId) {
        this.clientSessions.add(clientSessionId);
        return this;
    }

    public boolean validateSession(String emailAddress) {
        return this.emailAddress.equals(emailAddress);
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public Session setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
        return this;
    }

    public int getRetryCount() {
        return retryCount;
    }

    public int getPasswordResetCount() {
        return passwordResetCount;
    }

    public Session incrementPasswordResetCount() {
        this.passwordResetCount = passwordResetCount + 1;
        return this;
    }

    public Session resetPasswordResetCount() {
        this.passwordResetCount = 0;
        return this;
    }

    public int getCodeRequestCount() {
        return codeRequestCount;
    }

    public Session incrementCodeRequestCount() {
        this.codeRequestCount = codeRequestCount + 1;
        return this;
    }

    public Session resetCodeRequestCount() {
        this.codeRequestCount = 0;
        return this;
    }

    public CredentialTrustLevel getCurrentCredentialStrength() {
        return currentCredentialStrength;
    }

    public Session setCurrentCredentialStrength(CredentialTrustLevel currentCredentialStrength) {
        this.currentCredentialStrength = currentCredentialStrength;
        return this;
    }

    public AccountState isNewAccount() {
        return isNewAccount;
    }

    public Session setNewAccount(AccountState isNewAccount) {
        this.isNewAccount = isNewAccount;
        return this;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public Session setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
        return this;
    }

    public int getProcessingIdentityAttempts() {
        return processingIdentityAttempts;
    }

    public void resetProcessingIdentityAttempts() {
        this.processingIdentityAttempts = 0;
    }

    public int incrementProcessingIdentityAttempts() {
        this.processingIdentityAttempts += 1;
        return processingIdentityAttempts;
    }
}
