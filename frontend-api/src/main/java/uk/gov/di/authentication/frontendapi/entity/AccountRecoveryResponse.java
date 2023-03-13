package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class AccountRecoveryResponse {

    @SerializedName("accountRecoveryPermitted")
    @Expose
    private boolean accountRecoveryPermitted;

    public AccountRecoveryResponse(boolean accountRecoveryPermitted) {
        this.accountRecoveryPermitted = accountRecoveryPermitted;
    }

    public boolean getAccountRecoveryPermitted() {
        return accountRecoveryPermitted;
    }
}
