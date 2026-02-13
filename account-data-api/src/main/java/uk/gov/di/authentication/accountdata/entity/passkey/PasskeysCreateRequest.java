package uk.gov.di.authentication.accountdata.entity.passkey;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class PasskeysCreateRequest {

    @Expose @Required private String credential;

    @Expose
    @Required
    @SerializedName("id")
    private String passkeyId;

    @Expose @Required private String aaguid;

    @Expose @Required private String attestationSignature;

    public PasskeysCreateRequest() {}

    public PasskeysCreateRequest(
            String credential, String passkeyId, String aaguid, String attestationSignature) {
        this.credential = credential;
        this.passkeyId = passkeyId;
        this.aaguid = aaguid;
        this.attestationSignature = attestationSignature;
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

    public String getAttestationSignature() {
        return attestationSignature;
    }
}
