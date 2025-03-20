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
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodData;
import uk.gov.di.authentication.shared.entity.mfa.SmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.mfa.MfaMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason;

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

class MFAMethodsRetrieveHandlerTest {
    private final Context context = mock(Context.class);
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final String TEST_CLIENT = "test-client";
    private static final UserProfile userProfile =
            new UserProfile().withSubjectID(TEST_PUBLIC_SUBJECT).withEmail(EMAIL);
    private static final String TEST_INTERNAL_SUBJECT =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_PUBLIC_SUBJECT, "test.account.gov.uk", TEST_SALT);
    private static final MfaMethodsService mfaMethodsService = mock(MfaMethodsService.class);
    private static final String MFA_IDENTIFIER = "03a89933-cddd-471d-8fdb-562f14a2404f";

    private MFAMethodsRetrieveHandler handler;

    @BeforeEach
    void setUp() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler =
                new MFAMethodsRetrieveHandler(
                        configurationService, dynamoService, mfaMethodsService);
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);
    }

    @Test
    void shouldReturn200WithTheMethodReturnedByTheMfaMethodsService() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));

        var method =
                new MfaMethodData(
                        MFA_IDENTIFIER,
                        PriorityIdentifier.DEFAULT,
                        true,
                        new SmsMfaDetail("+44123456789"));
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Either.right(List.of(method)));

        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        var expectedBody =
                format(
                        "[{\"mfaIdentifier\":\"%s\",\"priorityIdentifier\":\"DEFAULT\",\"methodVerified\":true,\"method\":{\"mfaMethodType\":\"SMS\",\"phoneNumber\":\"+44123456789\"}}]",
                        MFA_IDENTIFIER);
        assertEquals(expectedBody, result.getBody());
    }

    @Test
    void shouldReturn400IfPublicSubjectIdNotIncludedInPath() {
        var event =
                generateApiGatewayEvent(TEST_INTERNAL_SUBJECT)
                        .withPathParameters((Map.of("publicSubjectId", "")));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn400IfRequestIsMadeInEnvironmentWhereApiIsDisabled() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);
        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn404IfNoUserProfileForPublicSubjectId() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.empty());
        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(404));
    }

    private static Stream<Arguments> mfaRetrieveFailureReasonsToExpectedErrors() {
        return Stream.of(
                Arguments.of(
                        MfaRetrieveFailureReason.ERROR_CONVERTING_MFA_METHOD_TO_MFA_METHOD_DATA,
                        500,
                        ErrorResponse.ERROR_1064),
                Arguments.of(
                        MfaRetrieveFailureReason
                                .UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP,
                        500,
                        ErrorResponse.ERROR_1078));
    }

    @ParameterizedTest
    @MethodSource("mfaRetrieveFailureReasonsToExpectedErrors")
    void shouldReturn500IfDynamoServiceReturnsError(
            MfaRetrieveFailureReason error,
            int expectedStatusCode,
            ErrorResponse expectedErrorResponse) {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Either.left(error));

        var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(expectedStatusCode));
        assertThat(result, hasJsonBody(expectedErrorResponse));
    }

    @Test
    void shouldReturn401IfPrincipalIsInvalid() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));

        var event = generateApiGatewayEvent("invalid-principal");

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1079));
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
                .withPathParameters((Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT)))
                .withHeaders(VALID_HEADERS)
                .withRequestContext(proxyRequestContext);
    }
}
