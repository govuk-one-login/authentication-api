package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.mfa.MfaDeleteFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaMethodsService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsDeleteHandlerTest {

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final Context context = mock(Context.class);
    private static final String MFA_IDENTIFIER_TO_DELETE = "8e18b315-995e-434e-a236-4fbfb72d6ce0";
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final String TEST_CLIENT = "test-client";
    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private static final UserProfile userProfile =
            new UserProfile().withSubjectID(TEST_PUBLIC_SUBJECT);
    private static final String TEST_INTERNAL_SUBJECT =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_PUBLIC_SUBJECT, "test.account.gov.uk", TEST_SALT);
    private static final MfaMethodsService mfaMethodsService = mock(MfaMethodsService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);

    private MFAMethodsDeleteHandler handler;

    @BeforeEach
    void setUp() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler =
                new MFAMethodsDeleteHandler(configurationService, mfaMethodsService, dynamoService);
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);
    }

    @Test
    void shouldReturn204WhenFeatureFlagEnabled() {
        when(mfaMethodsService.deleteMfaMethod(MFA_IDENTIFIER_TO_DELETE, userProfile))
                .thenReturn(Either.right(MFA_IDENTIFIER_TO_DELETE));
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));

        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

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
                        ErrorResponse.ERROR_1065));
    }

    @ParameterizedTest
    @MethodSource("failureReasonsToResponseCodes")
    void shouldReturnAppropriateResponseWhenMfaMethodsServiceIndicatesMethodCouldNotBeDeleted(
            MfaDeleteFailureReason failureReason,
            int expectedStatusCode,
            ErrorResponse expectedErrorResponse) {
        when(mfaMethodsService.deleteMfaMethod(MFA_IDENTIFIER_TO_DELETE, userProfile))
                .thenReturn(Either.left(failureReason));
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));

        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

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
                                (Map.of(
                                        "publicSubjectId",
                                        TEST_PUBLIC_SUBJECT,
                                        "mfaIdentifier",
                                        "")))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(eventWithoutMfaIdentifier, context);

        assertThat(result, hasStatus(400));
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
        var event = generateApiGatewayEvent("invalid-principal");
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1079));
    }

    @Test
    void shouldReturn404WhenUserProfileIsNotFoundForPublicSubject() {
        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.empty());

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
                        (Map.of(
                                "publicSubjectId",
                                TEST_PUBLIC_SUBJECT,
                                "mfaIdentifier",
                                MFAMethodsDeleteHandlerTest.MFA_IDENTIFIER_TO_DELETE)))
                .withHeaders(VALID_HEADERS)
                .withRequestContext(proxyRequestContext);
    }
}
