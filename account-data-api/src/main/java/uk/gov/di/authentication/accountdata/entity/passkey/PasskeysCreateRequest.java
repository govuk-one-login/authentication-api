package uk.gov.di.authentication.accountdata.entity.passkey;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public class PasskeysCreateRequest {

    @Expose
    @Required
    @SerializedName("id")
    private String passkeyId;

    @Expose @Required private String credential;

    @Expose @Required private String aaguid;

    @Expose @Required private boolean isAttested;

    @Expose @Required private int signCount;

    @Expose @Required private List<String> transports;

    @Expose @Required private boolean isBackUpEligible;

    @Expose @Required private boolean isBackedUp;

    @Expose @Required private boolean isResidentKey;

    public PasskeysCreateRequest() {}

    public PasskeysCreateRequest(
            String credential,
            String passkeyId,
            String aaguid,
            boolean isAttested,
            int signCount,
            List<String> transports,
            boolean isBackUpEligible,
            boolean isBackedUp,
            boolean isResidentKey) {
        this.credential = credential;
        this.passkeyId = passkeyId;
        this.aaguid = aaguid;
        this.isAttested = isAttested;
        this.signCount = signCount;
        this.transports = transports;
        this.isBackUpEligible = isBackUpEligible;
        this.isBackedUp = isBackedUp;
        this.isResidentKey = isResidentKey;
    }

    public String getCredential() {
        return credential;
    }

    public String getPasskeyId() {
        return passkeyId;
    }

    public String getAaguid() {
        return aaguid;
    }

    public boolean getIsAttested() {
        return isAttested;
    }

    public int getSignCount() {
        return signCount;
    }

    public List<String> getTransports() {
        return transports;
    }

    public boolean getIsBackUpEligible() {
        return isBackUpEligible;
    }

    public boolean getIsBackedUp() {
        return isBackedUp;
    }

    public boolean getIsResidentKey() {
        return isResidentKey;
    }
}
