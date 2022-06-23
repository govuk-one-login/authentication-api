package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.serialization.Base64ByteArrayAdapter;

import java.util.Map;

public class SPOTRequest {

    @SerializedName(value = "in_claims")
    @Expose
    private Map<String, Object> spotClaims;

    @SerializedName(value = "in_local_account_id")
    @Expose
    private String localAccountId;

    @SerializedName(value = "in_salt")
    @Expose
    @JsonAdapter(Base64ByteArrayAdapter.class)
    private byte[] salt;

    @SerializedName(value = "in_rp_sector_id")
    @Expose
    private String rpSectorId;

    @SerializedName(value = "out_sub")
    @Expose
    private String sub;

    @SerializedName(value = "log_ids")
    @Expose
    private LogIds logIds;

    @SerializedName(value = "out_audience")
    @Expose
    private String audience;

    public SPOTRequest(
            Map<String, Object> spotClaims,
            String localAccountId,
            byte[] salt,
            String rpSectorId,
            String sub,
            LogIds logIds,
            String audience) {
        this.spotClaims = spotClaims;
        this.localAccountId = localAccountId;
        this.salt = salt;
        this.rpSectorId = rpSectorId;
        this.sub = sub;
        this.logIds = logIds;
        this.audience = audience;
    }

    public SPOTRequest() {}

    public Map<String, Object> getSpotClaims() {
        return spotClaims;
    }

    public String getLocalAccountId() {
        return localAccountId;
    }

    public byte[] getSalt() {
        return salt;
    }

    public String getRpSectorId() {
        return rpSectorId;
    }

    public String getSub() {
        return sub;
    }

    public LogIds getLogIds() {
        return logIds;
    }

    public String getAudience() {
        return audience;
    }
}
