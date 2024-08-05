package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record AccountRecoveryResponse(
        @SerializedName("accountRecoveryPermitted") @Expose boolean accountRecoveryPermitted) {}
