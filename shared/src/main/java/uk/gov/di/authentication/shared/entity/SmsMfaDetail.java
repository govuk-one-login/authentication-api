package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record SmsMfaDetail(
        @Expose @Required MFAMethodType mfaMethodType, @Expose @Required String phoneNumber)
        implements MfaDetail {}
