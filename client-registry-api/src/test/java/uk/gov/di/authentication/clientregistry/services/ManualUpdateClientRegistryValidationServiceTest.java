package uk.gov.di.authentication.clientregistry.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.orchestration.shared.entity.ManualUpdateClientRegistryRequest;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.clientregistry.services.ManualUpdateClientRegistryValidationService.INVALID_RATE_LIMIT;

class ManualUpdateClientRegistryValidationServiceTest {

    private final ManualUpdateClientRegistryValidationService validationService =
            new ManualUpdateClientRegistryValidationService();

    private static final String CLIENT_ID = "client-id";

    @ParameterizedTest
    @ValueSource(strings = {"1", ""})
    void shouldPassValidationForValidUpdateRequest(String clientRateLimit) {
        Optional<ErrorObject> errorResponse =
                validationService.validateManualUpdateClientRegistryRequest(
                        ManualUpdateClientRegistryRequest(clientRateLimit));
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "-1", "1.5"})
    void shouldReturnErrorForInvalidClientRateLimitInUpdateRequest(String clientRateLimit) {
        Optional<ErrorObject> errorResponse =
                validationService.validateManualUpdateClientRegistryRequest(
                        ManualUpdateClientRegistryRequest(clientRateLimit));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_RATE_LIMIT)));
    }

    private ManualUpdateClientRegistryRequest ManualUpdateClientRegistryRequest(
            String clientRateLimit) {
        return new ManualUpdateClientRegistryRequest(CLIENT_ID, clientRateLimit);
    }
}
