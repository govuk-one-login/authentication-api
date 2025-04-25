package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.util.ArrayList;
import java.util.HashMap;
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

    @Expose private int passwordResetCount;

    @Expose private Map<CodeRequestType, Integer> codeRequestCountMap;

    @Expose private CredentialTrustLevel currentCredentialStrength;

    @Expose private AccountState isNewAccount;

    @Expose private boolean authenticated;

    @Expose private MFAMethodType verifiedMfaMethodType;

    @Expose private String internalCommonSubjectIdentifier;

    public Session() {
        this.clientSessions = new ArrayList<>();
        this.isNewAccount = AccountState.UNKNOWN;
        this.codeRequestCountMap = new HashMap<>();
        initializeCodeRequestMap();
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public Session setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
        return this;
    }

    private void initializeCodeRequestMap() {
        for (CodeRequestType requestType : CodeRequestType.values()) {
            codeRequestCountMap.put(requestType, 0);
        }
    }
}
