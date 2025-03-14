package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.MfaMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaDeleteFailureReason;

import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsDeleteHandlerTest {

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final Context context = mock(Context.class);
    private static final String PUBLIC_SUBJECT_ID = "some-subject-id";
    private static final String MFA_IDENTIFIER_TO_DELETE = "8e18b315-995e-434e-a236-4fbfb72d6ce0";
    private static final MfaMethodsService mfaMethodsService = mock(MfaMethodsService.class);

    private final APIGatewayProxyRequestEvent event =
            new APIGatewayProxyRequestEvent()
                    .withPathParameters(
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", PUBLIC_SUBJECT_ID),
                                    Map.entry("mfaIdentifier", MFA_IDENTIFIER_TO_DELETE)))
                    .withHeaders(VALID_HEADERS);

    private MFAMethodsDeleteHandler handler;

    @BeforeEach
    void setUp() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler = new MFAMethodsDeleteHandler(configurationService, mfaMethodsService);
    }

    @Test
    void shouldReturn204WhenFeatureFlagEnabled() {
        when(mfaMethodsService.deleteMfaMethod(PUBLIC_SUBJECT_ID, MFA_IDENTIFIER_TO_DELETE))
                .thenReturn(Either.right(MFA_IDENTIFIER_TO_DELETE));
        var result = handler.handleRequest(event, context);
        assertEquals(204, result.getStatusCode());
    }

    private static Stream<Arguments> failureReasonsToResponseCodes() {
        return Stream.of(
                Arguments.of(
                        MfaDeleteFailureReason.CANNOT_DELETE_DEFAULT_METHOD,
                        409,
                        ErrorResponse.ERROR_1066),
                Arguments.of(
                        MfaDeleteFailureReason.CANNOT_DELETE_MFA_METHOD_FOR_NON_MIGRATED_USER,
                        400,
                        ErrorResponse.ERROR_1067),
                Arguments.of(
                        MfaDeleteFailureReason.MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST,
                        404,
                        ErrorResponse.ERROR_1065),
                Arguments.of(
                        MfaDeleteFailureReason.NO_USER_PROFILE_FOUND_FOR_PUBLIC_SUBJECT_ID,
                        404,
                        ErrorResponse.ERROR_1056));
    }

    @ParameterizedTest
    @MethodSource("failureReasonsToResponseCodes")
    void shouldReturnAppropriateResponseWhenMfaMethodsServiceIndicatesMethodCouldNotBeDeleted(
            MfaDeleteFailureReason failureReason,
            int expectedStatusCode,
            ErrorResponse expectedErrorResponse) {
        when(mfaMethodsService.deleteMfaMethod(PUBLIC_SUBJECT_ID, MFA_IDENTIFIER_TO_DELETE))
                .thenReturn(Either.left(failureReason));

        var result = handler.handleRequest(event, context);
        assertEquals(expectedStatusCode, result.getStatusCode());
        assertThat(result, hasJsonBody(expectedErrorResponse));
    }

    @Test
    void shouldReturn400IfPublicSubjectIdNotIncludedInPath() {
        var eventWithoutPublicSubjectId =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters(
                                (Map.of(
                                        "publicSubjectId",
                                        "",
                                        "mfaIdentifier",
                                        MFA_IDENTIFIER_TO_DELETE)))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(eventWithoutPublicSubjectId, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn400IfMfaIdentifierNotIncludedInPath() {
        var eventWithoutMfaIdentifier =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters(
                                (Map.of("publicSubjectId", PUBLIC_SUBJECT_ID, "mfaIdentifier", "")))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(eventWithoutMfaIdentifier, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn400WhenFeatureFlagDisabled() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);

        var result = handler.handleRequest(event, context);
        assertEquals(400, result.getStatusCode());
    }
}
