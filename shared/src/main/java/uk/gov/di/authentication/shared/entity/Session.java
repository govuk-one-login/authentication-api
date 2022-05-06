package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;

import java.util.ArrayList;
import java.util.List;

public class Session {

    public enum AccountState {
        NEW,
        EXISTING,
        UNKNOWN
    }

    @JsonProperty("session_id")
    @Expose
    private String sessionId;

    @JsonProperty("client_sessions")
    @Expose
    private List<String> clientSessions;

    @JsonProperty("email_address")
    @Expose
    private String emailAddress;

    @JsonProperty("retry_count")
    @Expose
    private int retryCount;

    @JsonProperty("password_reset_count")
    @Expose
    private int passwordResetCount;

    @JsonProperty("code_request_count")
    @Expose
    private int codeRequestCount;

    @JsonProperty("current_credential_strength")
    @Expose
    private CredentialTrustLevel currentCredentialStrength;

    @JsonProperty("is_new_account")
    @Expose
    private AccountState isNewAccount;

    @JsonProperty("authenticated")
    @Expose
    private boolean authenticated;

    public Session(String sessionId) {
        this.sessionId = sessionId;
        this.clientSessions = new ArrayList<>();
        this.isNewAccount = AccountState.UNKNOWN;
    }

    @JsonCreator
    public Session(
            @JsonProperty("session_id") String sessionId,
            @JsonProperty("client_sessions") List<String> clientSessions,
            @JsonProperty("email_address") String emailAddress) {
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

    public Session incrementRetryCount() {
        this.retryCount = retryCount + 1;
        return this;
    }

    public Session resetRetryCount() {
        this.retryCount = 0;
        return this;
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
}
