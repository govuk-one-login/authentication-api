package uk.gov.di.authentication.clientregistry.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import uk.gov.di.orchestration.shared.entity.ManualUpdateClientRegistryRequest;

import java.util.Optional;

public class ManualUpdateClientRegistryValidationService {

    public static final ErrorObject INVALID_RATE_LIMIT =
            new ErrorObject("invalid_rate_limit", "Invalid client rate limit");

    public Optional<ErrorObject> validateManualUpdateClientRegistryRequest(
            ManualUpdateClientRegistryRequest updateRequest) {
        if (updateRequest.rateLimit() != null && !isRateLimitValid(updateRequest.rateLimit())) {
            return Optional.of(INVALID_RATE_LIMIT);
        }
        return Optional.empty();
    }

    private boolean isRateLimitValid(String clientRateLimit) {
        if (!clientRateLimit.isBlank()) {
            try {
                return Integer.parseInt(clientRateLimit) >= 0;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }
}
