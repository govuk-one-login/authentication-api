package uk.gov.di.authentication.shared.helpers;

import com.google.gson.JsonElement;
import uk.gov.di.authentication.shared.entity.EmailCheckResponse;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;

import java.util.Optional;

public class EmailCheckResultExtractorHelper {

    public static JsonElement getEmailFraudCheckResponseJsonFromResult(
            EmailCheckResultStore emailCheckResult) {
        return Optional.ofNullable(emailCheckResult.getEmailCheckResponse())
                .map(EmailCheckResponse::extensions)
                .map(res -> res.getAsJsonObject())
                .map(json -> json.get("emailFraudCheckResponse"))
                .orElse(null);
    }

    public static JsonElement getRestrictedJsonFromResult(EmailCheckResultStore emailCheckResult) {
        return Optional.ofNullable(emailCheckResult.getEmailCheckResponse())
                .map(EmailCheckResponse::restricted)
                .orElse(null);
    }
}
