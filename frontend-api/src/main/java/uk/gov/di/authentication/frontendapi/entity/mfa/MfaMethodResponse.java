package uk.gov.di.authentication.frontendapi.entity.mfa;

import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

public sealed interface MfaMethodResponse permits SmsMfaMethodResponse, AuthAppMfaMethodResponse {
    String id();

    PriorityIdentifier priority();

    MFAMethodType type();
}
