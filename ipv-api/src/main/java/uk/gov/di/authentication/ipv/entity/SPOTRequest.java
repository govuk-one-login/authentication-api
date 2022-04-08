package uk.gov.di.authentication.ipv.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SPOTRequest {

    @JsonProperty(value = "in_claims")
    private SPOTClaims spotClaims;

    @JsonProperty(value = "in_local_account_id")
    private String localAccountId;

    @JsonProperty(value = "in_salt")
    private byte[] salt;

    @JsonProperty(value = "in_rp_sector_id")
    private String rpSectorId;

    @JsonProperty(value = "out_sub")
    private String sub;

    @JsonProperty(value = "log_ids")
    private LogIds logIds;

    public SPOTRequest(
            SPOTClaims spotClaims,
            String localAccountId,
            byte[] salt,
            String rpSectorId,
            String sub,
            LogIds logIds) {
        this.spotClaims = spotClaims;
        this.localAccountId = localAccountId;
        this.salt = salt;
        this.rpSectorId = rpSectorId;
        this.sub = sub;
        this.logIds = logIds;
    }

    public SPOTRequest() {}

    public SPOTClaims getSpotClaims() {
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
}
