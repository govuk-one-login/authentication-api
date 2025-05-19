package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public class Session {

    private static final Logger LOG = LogManager.getLogger(Session.class);

    public enum AccountState {
        NEW,
        EXISTING,
        EXISTING_DOC_APP_JOURNEY,
        UNKNOWN
    }

    @Expose private String sessionId;
    @Expose private List<String> clientSessions;

    @Expose private String emailAddress;

    @Expose private int retryCount;

    @Expose private Map<CodeRequestType, Integer> codeRequestCountMap;

    @Expose private CredentialTrustLevel currentCredentialStrength;

    @Expose private AccountState isNewAccount;

    @Expose private boolean authenticated;

    @Expose private int processingIdentityAttempts;

    @Expose private MFAMethodType verifiedMfaMethodType;

    @Expose private String internalCommonSubjectIdentifier;

    public Session() {
        this.clientSessions = new ArrayList<>();
        this.isNewAccount = AccountState.UNKNOWN;
        this.processingIdentityAttempts = 0;
        this.codeRequestCountMap = new EnumMap<>(CodeRequestType.class);
        initializeCodeRequestMap();
    }

    public Session(Session session) {
        this.clientSessions = session.clientSessions;
        this.isNewAccount = session.isNewAccount;
        this.processingIdentityAttempts = session.processingIdentityAttempts;
        this.codeRequestCountMap = session.codeRequestCountMap;
        this.authenticated = session.authenticated;
        this.currentCredentialStrength = session.currentCredentialStrength;
        this.emailAddress = session.emailAddress;
        this.internalCommonSubjectIdentifier = session.internalCommonSubjectIdentifier;
        this.retryCount = session.retryCount;
        this.verifiedMfaMethodType = session.verifiedMfaMethodType;
        initializeCodeRequestMap();
    }

    public boolean validateSession(String emailAddress) {
        return this.emailAddress.equals(emailAddress);
    }

    public CredentialTrustLevel getCurrentCredentialStrength() {
        return currentCredentialStrength;
    }

    public Session setCurrentCredentialStrength(CredentialTrustLevel currentCredentialStrength) {
        this.currentCredentialStrength = currentCredentialStrength;
        return this;
    }

    public Session setNewAccount(AccountState isNewAccount) {
        this.isNewAccount = isNewAccount;
        return this;
    }

    public Session setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
        return this;
    }

    private void initializeCodeRequestMap() {
        for (CodeRequestType requestType : CodeRequestType.values()) {
            codeRequestCountMap.put(requestType, 0);
        }
    }
}
