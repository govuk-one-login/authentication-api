package uk.gov.di.authentication.frontendapi.helpers;

import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.ArrayList;
import java.util.Map;

import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class ReauthMetadataBuilder {
    private final AuditService.MetadataPair rpPairwiseIdPair;
    private AuditService.MetadataPair incorrectEmailAttemptCountPair;
    private AuditService.MetadataPair incorrectPasswordAttemptCount;
    private AuditService.MetadataPair incorrectOtpAttemptCount;
    private AuditService.MetadataPair failureReason;

    private ReauthMetadataBuilder(String rpPairwiseId) {
        this.rpPairwiseIdPair = pair("rp_pairwise_id", rpPairwiseId);
    }

    public static ReauthMetadataBuilder builder(String rpPairwiseId) {
        return new ReauthMetadataBuilder(rpPairwiseId);
    }

    public ReauthMetadataBuilder withAllIncorrectAttemptCounts(
            Map<CountType, Integer> countsByJourney) {
        this.incorrectEmailAttemptCountPair =
                pair(
                        "incorrect_email_attempt_count",
                        countsByJourney.getOrDefault(CountType.ENTER_EMAIL, 0));
        this.incorrectPasswordAttemptCount =
                pair(
                        "incorrect_password_attempt_count",
                        countsByJourney.getOrDefault(CountType.ENTER_PASSWORD, 0));
        this.incorrectOtpAttemptCount =
                pair(
                        "incorrect_otp_code_attempt_count",
                        (countsByJourney.getOrDefault(CountType.ENTER_SMS_CODE, 0))
                                + (countsByJourney.getOrDefault(CountType.ENTER_AUTH_APP_CODE, 0)));
        return this;
    }

    public ReauthMetadataBuilder withFailureReason(ReauthFailureReasons failureReason) {
        this.failureReason = pair("failure-reason", failureReason.getValue());
        return this;
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
        return metadataPairs.toArray(AuditService.MetadataPair[]::new);
    }
}
