package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.google.gson.JsonParser;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.response.MfaMethodResponse;
import uk.gov.di.authentication.shared.entity.mfa.response.ResponseSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsCreateHandlerTest {
    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(MFAMethodsCreateHandler.class);

    private final Context context = mock(Context.class);
    private static final String TEST_PHONE_NUMBER = "07123123123";
    private static final String TEST_EMAIL = "test@test.com";
    private static final String TEST_SMS_MFA_ID = "35c7940d-be5f-4b31-95b7-0eedc42929b9";
    private static final String TEST_AUTH_APP_ID = "f2ec40f3-9e63-496c-a0a5-a3bdafee868b";
    private static final String TEST_CREDENTIAL = "ZZ11BB22CC33DD44EE55FF66GG77HH88II99JJ00";
    private static final String TEST_CLIENT_ID = "some-client-id";
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private static final UserProfile userProfile =
            new UserProfile().withSubjectID(TEST_PUBLIC_SUBJECT).withEmail(TEST_EMAIL);
    private static final String TEST_INTERNAL_SUBJECT =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_PUBLIC_SUBJECT, "test.account.gov.uk", TEST_SALT);

    private MFAMethodsCreateHandler handler;

    @BeforeEach
    void setUp() {
        reset(mfaMethodsService);
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler =
                new MFAMethodsCreateHandler(configurationService, mfaMethodsService, dynamoService);
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        reset(mfaMethodsService);
        when(mfaMethodsService.migrateMfaCredentialsForUser(any())).thenReturn(Optional.empty());
    }

    private static Stream<Arguments> migrationFailureReasonsToExpectedResponses() {
        return Stream.of(
                Arguments.of(
                        MfaMigrationFailureReason.NO_USER_FOUND_FOR_EMAIL,
                        ErrorResponse.ERROR_1056,
                        400),
                Arguments.of(
                        MfaMigrationFailureReason.UNEXPECTED_ERROR_RETRIEVING_METHODS,
                        ErrorResponse.ERROR_1064,
                        500));
    }

    @ParameterizedTest
    @MethodSource("migrationFailureReasonsToExpectedResponses")
    void shouldReturnRelevantStatusCodeWhenMigrationFailed(
            MfaMigrationFailureReason reason, ErrorResponse expectedError, int expectedStatusCode) {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.migrateMfaCredentialsForUser(any())).thenReturn(Optional.of(reason));

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"),
                        TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(expectedStatusCode));
        assertTrue(result.getBody().contains(String.valueOf(expectedError.getCode())));
        assertTrue(result.getBody().contains(expectedError.getMessage()));
    }

    @Test
    void shouldReturn200AndCreateMfaSmsMfaMethod() {
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(
                        Result.success(
                                new MfaMethodResponse(
                                        TEST_SMS_MFA_ID,
                                        PriorityIdentifier.BACKUP,
                                        true,
                                        new ResponseSmsMfaDetail(TEST_PHONE_NUMBER))));

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"),
                        TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        ArgumentCaptor<MfaMethodCreateOrUpdateRequest.MfaMethod> mfaMethodCaptor =
                ArgumentCaptor.forClass(MfaMethodCreateOrUpdateRequest.MfaMethod.class);

        verify(mfaMethodsService).addBackupMfa(eq(TEST_EMAIL), mfaMethodCaptor.capture());
        var capturedRequest = mfaMethodCaptor.getValue();

        assertEquals(
                new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"), capturedRequest.method());
        assertEquals(PriorityIdentifier.BACKUP, capturedRequest.priorityIdentifier());

        assertThat(result, hasStatus(200));
        var expectedResponse =
                format(
                        """
                {
                  "mfaIdentifier": "%s",
                  "priorityIdentifier": "BACKUP",
                  "methodVerified": true,
                  "method": {
                    "mfaMethodType": "SMS",
                    "phoneNumber": "%s"
                  }
                }
                """,
                        TEST_SMS_MFA_ID, TEST_PHONE_NUMBER);
        var expectedResponseParsedToString =
                JsonParser.parseString(expectedResponse).getAsJsonObject().toString();
        assertEquals(expectedResponseParsedToString, result.getBody());
    }

    @Test
    void shouldReturn200AndCreateAuthAppMfa() {
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(
                        Result.success(
                                new MfaMethodResponse(
                                        TEST_AUTH_APP_ID,
                                        PriorityIdentifier.BACKUP,
                                        true,
                                        new RequestAuthAppMfaDetail(TEST_CREDENTIAL))));

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        ArgumentCaptor<MfaMethodCreateOrUpdateRequest.MfaMethod> mfaMethodCaptor =
                ArgumentCaptor.forClass(MfaMethodCreateOrUpdateRequest.MfaMethod.class);

        verify(mfaMethodsService).addBackupMfa(eq(TEST_EMAIL), mfaMethodCaptor.capture());
        var capturedRequest = mfaMethodCaptor.getValue();

        assertEquals(new RequestAuthAppMfaDetail(TEST_CREDENTIAL), capturedRequest.method());
        assertEquals(PriorityIdentifier.BACKUP, capturedRequest.priorityIdentifier());

        assertThat(result, hasStatus(200));
        var expectedResponse =
                format(
                        """
                {
                  "mfaIdentifier": "%s",
                  "priorityIdentifier": "BACKUP",
                  "methodVerified": true,
                  "method": {
                    "mfaMethodType": "AUTH_APP",
                    "credential": "%s"
                  }
                }
                """,
                        TEST_AUTH_APP_ID, TEST_CREDENTIAL);
        var expectedResponseParsedToString =
                JsonParser.parseString(expectedResponse).getAsJsonObject().toString();
        assertEquals(expectedResponseParsedToString, result.getBody());
    }

    @Test
    void shouldReturn400IfRequestIsMadeInEnvWhereApiNotEnabled() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn400WhenPathParameterIsEmpty() {
        var event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of());

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Subject missing from request prevents request being handled.")));
    }

    @Test
    void shouldReturn404WhenUserProfileNotFoundForPublicSubject() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.empty());

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(404));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));
    }

    @Test
    void shouldReturn400WhenJsonIsInvalid() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"),
                        TEST_INTERNAL_SUBJECT);
        event.setBody("Invalid JSON");

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400WhenRequestToCreateNewDefault() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.DEFAULT,
                        new SmsMfaDetail(TEST_PHONE_NUMBER),
                        TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1080));
    }

    @Test
    void shouldReturn400WhenMfaMethodServiceReturnsBackupAndDefaultExistError() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"),
                        TEST_INTERNAL_SUBJECT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(
                        Result.failure(
                                MfaCreateFailureReason.BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1068));
    }

    @Test
    void shouldReturn400WhenMfaMethodServiceReturnsSmsMfaAlreadyExistsError() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"),
                        TEST_INTERNAL_SUBJECT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(Result.failure(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1069));
    }

    @Test
    void shouldReturn400WhenMfaMethodServiceReturnsAuthAppAlreadyExistsError() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_INTERNAL_SUBJECT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(Result.failure(MfaCreateFailureReason.AUTH_APP_EXISTS));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1070));
    }

    @Test
    void shouldReturn500WhenMfaMethodServiceReturnsRetrieveError() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_INTERNAL_SUBJECT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(Result.failure(MfaCreateFailureReason.ERROR_RETRIEVING_MFA_METHODS));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1071));
    }

    @Test
    void shouldReturn401WhenPrincipalIsInvalid() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                        "invalid");

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1079));
    }

    private APIGatewayProxyRequestEvent generateApiGatewayEvent(
            PriorityIdentifier priorityIdentifier, MfaDetail mfaDetail, String principal) {

        String body =
                mfaDetail instanceof RequestSmsMfaDetail
                        ? format(
                                """
                                { "mfaMethod": {
                                    "priorityIdentifier": "%s",
                                    "method": {
                                        "mfaMethodType": "SMS",
                                        "phoneNumber": "%s",
                                        "otp": "%s"
                                    }
                                    }
                                }
                               """,
                                priorityIdentifier,
                                ((RequestSmsMfaDetail) mfaDetail).phoneNumber(),
                                ((RequestSmsMfaDetail) mfaDetail).otp())
                        : format(
                                """
                                { "mfaMethod": {
                                    "priorityIdentifier": "%s",
                                    "method": {
                                        "mfaMethodType": "AUTH_APP",
                                        "credential": "%s" }
                                    }
                                }
                               """,
                                priorityIdentifier,
                                ((RequestAuthAppMfaDetail) mfaDetail).credential());

        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", principal);
        authorizerParams.put("clientId", TEST_CLIENT_ID);
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));

        return new APIGatewayProxyRequestEvent()
                .withPathParameters(Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT))
                .withBody(body)
                .withRequestContext(proxyRequestContext)
                .withHeaders(VALID_HEADERS);
    }
}
