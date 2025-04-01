package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.google.gson.JsonParser;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodData;
import uk.gov.di.authentication.shared.entity.mfa.SmsMfaDetail;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MfaMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaUpdateFailureReason;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsPutHandlerTest {

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final MfaMethodsService mfaMethodsService = mock(MfaMethodsService.class);
    private static final AuthenticationService authenticationService =
            mock(AuthenticationService.class);
    private static final UserProfile userProfile = mock(UserProfile.class);
    private static final Context context = mock(Context.class);
    private static final String MFA_IDENTIFIER = "some-mfa-identifier";
    private static final String PUBLIC_SUBJECT_ID = "some-subject-id";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";

    private MFAMethodsPutHandler handler;

    private final APIGatewayProxyRequestEvent event =
            new APIGatewayProxyRequestEvent()
                    .withPathParameters(
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", PUBLIC_SUBJECT_ID),
                                    Map.entry("mfaIdentifier", MFA_IDENTIFIER)))
                    .withHeaders(VALID_HEADERS);

    @BeforeEach
    void setUp() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler =
                new MFAMethodsPutHandler(
                        configurationService, mfaMethodsService, authenticationService);
    }

    @Test
    void shouldReturn200WithUpdatedMethodWhenFeatureFlagEnabled() {
        var phoneNumber = "123456789";
        var updateRequest =
                MfaMethodCreateOrUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new SmsMfaDetail(phoneNumber));
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber));

        when(userProfile.getEmail()).thenReturn(EMAIL);
        when(authenticationService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.of(userProfile));

        var updatedMfaMethod =
                MfaMethodData.smsMethodData(
                        MFA_IDENTIFIER, PriorityIdentifier.DEFAULT, true, phoneNumber);
        when(mfaMethodsService.updateMfaMethod(EMAIL, MFA_IDENTIFIER, updateRequest))
                .thenReturn(Either.right(List.of(updatedMfaMethod)));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(200, result.getStatusCode());
        var expectedResponse =
                format(
                        """
                [{
                  "mfaIdentifier": "%s",
                  "priorityIdentifier": "DEFAULT",
                  "methodVerified": true,
                  "method": {
                    "mfaMethodType": "SMS",
                    "phoneNumber": "%s"
                  }
                }]
                """,
                        MFA_IDENTIFIER, phoneNumber);
        var expectedResponseParsedToString =
                JsonParser.parseString(expectedResponse).getAsJsonArray().toString();
        assertEquals(expectedResponseParsedToString, result.getBody());
    }

    private static Stream<Arguments> updateFailureReasonsToExpectedResponses() {
        return Stream.of(
                Arguments.of(
                        MfaUpdateFailureReason.CANNOT_CHANGE_TYPE_OF_MFA_METHOD,
                        400,
                        Optional.of(ErrorResponse.ERROR_1072)),
                Arguments.of(
                        MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE,
                        204,
                        Optional.empty()),
                Arguments.of(
                        MfaUpdateFailureReason.UNEXPECTED_ERROR,
                        500,
                        Optional.of(ErrorResponse.ERROR_1071)),
                Arguments.of(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_PHONE_NUMBER_WITH_BACKUP_NUMBER,
                        400,
                        Optional.of(ErrorResponse.ERROR_1074)),
                Arguments.of(
                        MfaUpdateFailureReason.CANNOT_CHANGE_PRIORITY_OF_DEFAULT_METHOD,
                        400,
                        Optional.of(ErrorResponse.ERROR_1073)),
                Arguments.of(
                        MfaUpdateFailureReason.UNKOWN_MFA_IDENTIFIER,
                        404,
                        Optional.of(ErrorResponse.ERROR_1065)),
                Arguments.of(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_METHOD_AUTH_APP_CREDENTIAL,
                        400,
                        Optional.of(ErrorResponse.ERROR_1076)),
                Arguments.of(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_METHOD_PHONE_NUMBER,
                        400,
                        Optional.of(ErrorResponse.ERROR_1075)),
                Arguments.of(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_WITH_NO_DEFAULT_METHOD,
                        500,
                        Optional.of(ErrorResponse.ERROR_1077)));
    }

    @ParameterizedTest
    @MethodSource("updateFailureReasonsToExpectedResponses")
    void shouldReturnAppropriateResponseWhenMfaMethodsServiceReturnsError(
            MfaUpdateFailureReason failureReason,
            int expectedStatus,
            Optional<ErrorResponse> maybeErrorResponse) {
        when(userProfile.getEmail()).thenReturn(EMAIL);
        when(authenticationService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.of(userProfile));

        var phoneNumber = "123456789";
        var updateRequest =
                MfaMethodCreateOrUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new SmsMfaDetail(phoneNumber));

        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber));
        when(mfaMethodsService.updateMfaMethod(EMAIL, MFA_IDENTIFIER, updateRequest))
                .thenReturn(Either.left(failureReason));
        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertThat(result, hasStatus(expectedStatus));
        maybeErrorResponse.ifPresent(
                expectedError -> assertThat(result, hasJsonBody(expectedError)));
    }

    @Test
    void shouldReturn400WhenJsonIsInvalid() {
        event.withBody("Invalid JSON");
        when(authenticationService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.of(userProfile));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400WhenPathParameterIsEmpty() {
        event.withPathParameters(
                Map.of("mfaIdentifier", "some-mfa-identifier", "publicSubjectId", ""));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400WhenMfaIdentifierParameterIsEmpty() {
        event.withPathParameters(
                Map.of("publicSubjectId", "some-public-subject-id", "mfaIdentifier", ""));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn404WhenUserProfileNotFoundForPublicSubject() {
        when(authenticationService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.empty());

        event.withBody(updateSmsRequest("123456789"));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(404));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));
    }

    @Test
    void shouldReturn400WhenFeatureFlagDisabled() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);

        var result = handler.handleRequest(event, context);
        assertEquals(400, result.getStatusCode());
    }

    private String updateSmsRequest(String phoneNumber) {
        return format(
                """
        {
          "mfaMethod": {
            "priorityIdentifier": "DEFAULT",
            "method": {
                "mfaMethodType": "SMS",
                "phoneNumber": "%s"
            }
          }
        }
        """,
                phoneNumber);
    }
}
