package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.google.gson.JsonParser;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.response.MfaMethodResponse;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaUpdateFailureReason;

import java.util.HashMap;
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
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsPutHandlerTest {

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private static final AuthenticationService authenticationService =
            mock(AuthenticationService.class);
    private static final Context context = mock(Context.class);
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final String TEST_CLIENT = "test-client";
    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final UserProfile userProfile =
            new UserProfile().withSubjectID(TEST_PUBLIC_SUBJECT).withEmail(EMAIL);
    private static final String TEST_INTERNAL_SUBJECT =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_PUBLIC_SUBJECT, "test.account.gov.uk", TEST_SALT);
    private static final String MFA_IDENTIFIER = "some-mfa-identifier";

    private MFAMethodsPutHandler handler;

    @BeforeEach
    void setUp() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);
        handler =
                new MFAMethodsPutHandler(
                        configurationService, mfaMethodsService, authenticationService);
    }

    @Test
    void shouldReturn200WithUpdatedMethodWhenFeatureFlagEnabled() {
        var phoneNumber = "123456789";
        var updateRequest =
                MfaMethodCreateOrUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestSmsMfaDetail(phoneNumber, "123456"));
        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, "123456"));

        when(authenticationService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));

        var updatedMfaMethod =
                MfaMethodResponse.smsMethodData(
                        MFA_IDENTIFIER, PriorityIdentifier.DEFAULT, true, phoneNumber);
        when(mfaMethodsService.updateMfaMethod(EMAIL, MFA_IDENTIFIER, updateRequest))
                .thenReturn(Result.success(List.of(updatedMfaMethod)));

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
        when(authenticationService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));

        var phoneNumber = "123456789";
        var updateRequest =
                MfaMethodCreateOrUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestSmsMfaDetail(phoneNumber, "123456"));

        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, "123456"));
        when(mfaMethodsService.updateMfaMethod(EMAIL, MFA_IDENTIFIER, updateRequest))
                .thenReturn(Result.failure(failureReason));
        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertThat(result, hasStatus(expectedStatus));
        maybeErrorResponse.ifPresent(
                expectedError -> assertThat(result, hasJsonBody(expectedError)));
    }

    @Test
    void shouldReturn400WhenJsonIsInvalid() {
        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT).withBody("Invalid JSON");
        when(authenticationService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400WhenPathParameterIsEmpty() {
        var event =
                generateApiGatewayEvent(TEST_INTERNAL_SUBJECT)
                        .withPathParameters(
                                Map.of(
                                        "mfaIdentifier",
                                        "some-mfa-identifier",
                                        "publicSubjectId",
                                        ""));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400WhenMfaIdentifierParameterIsEmpty() {
        var event =
                generateApiGatewayEvent(TEST_INTERNAL_SUBJECT)
                        .withPathParameters(
                                Map.of(
                                        "publicSubjectId",
                                        "some-public-subject-id",
                                        "mfaIdentifier",
                                        ""));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400WhenFeatureFlagDisabled() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);

        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);
        assertEquals(400, result.getStatusCode());
    }

    @Test
    void shouldReturn401WhenPrincipalIsInvalid() {
        when(authenticationService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));

        var event = generateApiGatewayEvent("invalid-principal");

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1079));
    }

    @Test
    void shouldReturn404WhenUserProfileIsNotFoundForPublicSubject() {
        when(authenticationService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.empty());

        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(404));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));
    }

    private static APIGatewayProxyRequestEvent generateApiGatewayEvent(String principal) {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", principal);
        authorizerParams.put("clientId", TEST_CLIENT);
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));

        return new APIGatewayProxyRequestEvent()
                .withPathParameters(
                        Map.ofEntries(
                                Map.entry("publicSubjectId", TEST_PUBLIC_SUBJECT),
                                Map.entry("mfaIdentifier", MFA_IDENTIFIER)))
                .withHeaders(VALID_HEADERS)
                .withRequestContext(proxyRequestContext);
    }

    private String updateSmsRequest(String phoneNumber, String otp) {
        return format(
                """
        {
          "mfaMethod": {
            "priorityIdentifier": "DEFAULT",
            "method": {
                "mfaMethodType": "SMS",
                "phoneNumber": "%s",
                "otp": "%s"
            }
          }
        }
        """,
                phoneNumber, otp);
    }
}
