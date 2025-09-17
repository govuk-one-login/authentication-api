package uk.gov.di.authentication.frontendapi.anticorruptionlayer;

import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;

public class ForbiddenReasonAntiCorruption {

    private ForbiddenReasonAntiCorruption() {}

    public static ReauthFailureReasons toReauthFailureReason(ForbiddenReason decisionError) {
        return switch (decisionError) {
            case EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT -> ReauthFailureReasons
                    .INCORRECT_EMAIL;
            case EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT -> ReauthFailureReasons
                    .INCORRECT_PASSWORD;
            case EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT -> ReauthFailureReasons.INCORRECT_OTP;
            default -> null;
        };
    }
}
