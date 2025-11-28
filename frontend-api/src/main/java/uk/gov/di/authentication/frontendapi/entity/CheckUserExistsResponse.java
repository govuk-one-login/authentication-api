package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.userpermissions.entity.LockoutInformation;

import java.util.List;

public record CheckUserExistsResponse(
        @SerializedName("email") @Expose String email,
        @SerializedName("doesUserExist") @Expose boolean doesUserExist,
        @SerializedName("mfaMethodType") @Expose MFAMethodType mfaMethodType,
        @SerializedName("phoneNumberLastThree") @Expose String phoneNumberLastThree,
        @SerializedName("lockoutInformation") @Expose List<LockoutInformation> lockoutInformation,
        @SerializedName("hasActivePasskey") @Expose boolean hasActivePasskey) {}
