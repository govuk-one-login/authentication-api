package uk.gov.di.authentication.frontendapi.helpers;

import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class ReauthMetadataBuilder {
    private final AuditService.MetadataPair rpPairwiseIdPair;
    private AuditService.MetadataPair incorrectEmailAttemptCountPair;
    private AuditService.MetadataPair incorrectPasswordAttemptCount;
    private AuditService.MetadataPair incorrectOtpAttemptCount;
    private AuditService.MetadataPair failureReason;
    private AuditService.MetadataPair restrictedUserSuppliedEmailPair;
    private AuditService.MetadataPair restrictedUserIdForUserSuppliedEmailPair;

    private ReauthMetadataBuilder(String rpPairwiseId) {
        this.rpPairwiseIdPair = pair("rpPairwiseId", rpPairwiseId);
    }

    public static ReauthMetadataBuilder builder(String rpPairwiseId) {
        return new ReauthMetadataBuilder(rpPairwiseId);
    }

    public ReauthMetadataBuilder withAllIncorrectAttemptCounts(
            Map<CountType, Integer> countsByJourney) {
        withIncorrectEmailCount(countsByJourney.getOrDefault(CountType.ENTER_EMAIL, 0));
        this.incorrectPasswordAttemptCount =
                pair(
                        "incorrect_password_attempt_count",
                        countsByJourney.getOrDefault(CountType.ENTER_PASSWORD, 0));
        this.incorrectOtpAttemptCount =
                pair(
                        "incorrect_otp_code_attempt_count",
                        (countsByJourney.getOrDefault(CountType.ENTER_MFA_CODE, 0)));
        return this;
    }

    public ReauthMetadataBuilder withIncorrectEmailCount(Integer count) {
        this.incorrectEmailAttemptCountPair = pair("incorrect_email_attempt_count", count);
        return this;
    }

    public ReauthMetadataBuilder withRestrictedUserSuppliedEmailPair(String userSuppliedEmail) {
        this.restrictedUserSuppliedEmailPair = pair("user_supplied_email", userSuppliedEmail, true);
        return this;
    }

    public ReauthMetadataBuilder withRestrictedUserIdForUserSuppliedEmailPair(
            String userSuppliedEmail) {
        this.restrictedUserIdForUserSuppliedEmailPair =
                pair("user_id_for_user_supplied_email", userSuppliedEmail, true);
        return this;
    }

    public ReauthMetadataBuilder withFailureReason(ReauthFailureReasons failureReason) {
        this.failureReason =
                failureReason == null ? null : pair("failure-reason", failureReason.getValue());
        return this;
    }

    public ReauthMetadataBuilder withFailureReason(List<CountType> exceededCountTypes) {
        return withFailureReason(getReauthFailureReasonFromCountTypes(exceededCountTypes));
    }

    public static ReauthFailureReasons getReauthFailureReasonFromCountTypes(
            List<CountType> exceededCountTypes) {
        CountType exceededType = exceededCountTypes.get(0);
        return switch (exceededType) {
            case ENTER_EMAIL -> ReauthFailureReasons.INCORRECT_EMAIL;
            case ENTER_PASSWORD -> ReauthFailureReasons.INCORRECT_PASSWORD;
            case ENTER_MFA_CODE -> ReauthFailureReasons.INCORRECT_OTP;
            default -> null;
        };
    }

    public AuditService.MetadataPair[] build() {
        var metadataPairs = new ArrayList<AuditService.MetadataPair>();
        if (rpPairwiseIdPair != null) {
            metadataPairs.add(rpPairwiseIdPair);
        }
        if (incorrectEmailAttemptCountPair != null) {
            metadataPairs.add(incorrectEmailAttemptCountPair);
        }
        if (incorrectPasswordAttemptCount != null) {
            metadataPairs.add(incorrectPasswordAttemptCount);
        }
        if (incorrectOtpAttemptCount != null) {
            metadataPairs.add(incorrectOtpAttemptCount);
        }
        if (failureReason != null) {
            metadataPairs.add(failureReason);
        }
        if (restrictedUserSuppliedEmailPair != null) {
            metadataPairs.add(restrictedUserSuppliedEmailPair);
        }
        if (restrictedUserIdForUserSuppliedEmailPair != null) {
            metadataPairs.add(restrictedUserIdForUserSuppliedEmailPair);
        }
        return metadataPairs.toArray(AuditService.MetadataPair[]::new);
    }
}
