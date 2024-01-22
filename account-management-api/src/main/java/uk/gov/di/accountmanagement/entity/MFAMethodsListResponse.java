package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public record MFAMethodsListResponse(@Expose @Required List<MFAMethod> mfaMethodList) {}
