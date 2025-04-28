package uk.gov.di.authentication.frontendapi.entity.mfa;

import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import static uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper.redactPhoneNumber;

public sealed interface MfaMethodResponse permits SmsMfaMethodResponse, AuthAppMfaMethodResponse {
    String id();

    PriorityIdentifier priority();

    MFAMethodType type();

    static Result<String, MfaMethodResponse> from(MFAMethod mfaMethod) {
        String id = mfaMethod.getMfaIdentifier();
        MFAMethodType type;
        try {
            type = MFAMethodType.valueOf(mfaMethod.getMfaMethodType());
        } catch (NullPointerException | IllegalArgumentException e) {
            return Result.failure("Unsupported MFA method type: " + mfaMethod.getMfaMethodType());
        }

        PriorityIdentifier priority;
        try {
            priority = PriorityIdentifier.valueOf(mfaMethod.getPriority());
        } catch (NullPointerException | IllegalArgumentException e) {
            return Result.failure("Unsupported PriorityIdentifier: " + mfaMethod.getPriority());
        }

        return switch (type) {
            case SMS -> {
                String phoneNumber = mfaMethod.getDestination();
                yield Result.success(
                        new SmsMfaMethodResponse(
                                id,
                                MFAMethodType.SMS,
                                priority,
                                phoneNumber != null ? redactPhoneNumber(phoneNumber) : null));
            }
            case AUTH_APP -> Result.success(
                    new AuthAppMfaMethodResponse(id, MFAMethodType.AUTH_APP, priority));
            default -> Result.failure(
                    "Unsupported MFA method type: " + mfaMethod.getMfaMethodType());
        };
    }
}
