package uk.gov.di.authentication.oidc.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.oidc.entity.ClientRequestInfo;
import uk.gov.di.authentication.oidc.entity.RateLimitAlgorithm;
import uk.gov.di.authentication.oidc.entity.RateLimitDecision;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.sharedtest.helper.Constants;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class RateLimitServiceTest {

    private static final RateLimitAlgorithm noActionAlgorithm =
            (client) -> RateLimitDecision.UNDER_LIMIT_NO_ACTION;
    private static final RateLimitAlgorithm alwaysReturnToRpAction =
            (client) -> RateLimitDecision.OVER_LIMIT_RETURN_TO_RP;

    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);

    @Test
    void itReturnsNoActionDecisionWhenTheClientHasNoRateLimit() {
        var rateLimitService =
                new RateLimitService(alwaysReturnToRpAction, cloudwatchMetricsService);
        var rateLimitDecision =
                rateLimitService.getClientRateLimitDecision(
                        new ClientRequestInfo(Constants.TEST_CLIENT_ID, null));
        assertFalse(rateLimitDecision.hasExceededRateLimit());
        assertEquals(RateLimitDecision.RateLimitAction.NONE, rateLimitDecision.getAction());

        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        "RpRateLimitExceeded",
                        Map.of(
                                "clientId",
                                Constants.TEST_CLIENT_ID,
                                "action",
                                RateLimitDecision.RateLimitAction.NONE.toString()));
    }

    @ParameterizedTest
    @MethodSource("rateLimitAlgosAndOutcomes")
    void itDelegatesToTheRateLimitAlgoWhenClientHasARateLimitConfigured(
            RateLimitAlgorithm algorithm, RateLimitDecision outcome) {
        var rateLimitService = new RateLimitService(algorithm, cloudwatchMetricsService);
        var rateLimitDecision =
                rateLimitService.getClientRateLimitDecision(
                        new ClientRequestInfo(Constants.TEST_CLIENT_ID, 400));
        assertEquals(outcome, rateLimitDecision);

        if (outcome.hasExceededRateLimit()) {
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            "RpRateLimitExceeded",
                            Map.of(
                                    "clientId",
                                    Constants.TEST_CLIENT_ID,
                                    "action",
                                    outcome.getAction().toString()));
        }
    }

    private static Stream<Arguments> rateLimitAlgosAndOutcomes() {
        return Stream.of(
                Arguments.of(noActionAlgorithm, RateLimitDecision.UNDER_LIMIT_NO_ACTION),
                Arguments.of(alwaysReturnToRpAction, RateLimitDecision.OVER_LIMIT_RETURN_TO_RP));
    }
}
