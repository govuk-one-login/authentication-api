package uk.gov.di.authentication.ipv.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SPOTClaims {

    @JsonProperty(value = "vot")
    private String vot;

    @JsonProperty(value = "vtm")
    private String vtm;

    public SPOTClaims(String vot, String vtm) {
        this.vot = vot;
        this.vtm = vtm;
    }

    public SPOTClaims() {}

    public String getVot() {
        return vot;
    }

    public String getVtm() {
        return vtm;
    }
}
