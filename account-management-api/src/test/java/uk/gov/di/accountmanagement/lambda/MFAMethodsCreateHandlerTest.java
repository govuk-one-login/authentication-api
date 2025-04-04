package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.google.gson.JsonParser;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodData;
import uk.gov.di.authentication.shared.entity.mfa.SmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

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
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsCreateHandlerTest {
    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(MFAMethodsCreateHandler.class);

    private final Context context = mock(Context.class);
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String SESSION_ID = "some-session-id";
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final String TEST_PHONE_NUMBER = "07123123123";
    private static final String TEST_PUBLIC_SUBJECT = "test-public-subject";
    private static final String TEST_EMAIL = "test@test.com";
    private static final String TEST_SMS_MFA_ID = "35c7940d-be5f-4b31-95b7-0eedc42929b9";
    private static final String TEST_AUTH_APP_ID = "f2ec40f3-9e63-496c-a0a5-a3bdafee868b";
    private static final String TEST_CREDENTIAL = "ZZ11BB22CC33DD44EE55FF66GG77HH88II99JJ00";
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final MfaMethodsService mfaMethodsService = mock(MfaMethodsService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private static final UserProfile userProfile = mock(UserProfile.class);

    private MFAMethodsCreateHandler handler;

    @BeforeEach
    void setUp() {
        reset(mfaMethodsService);
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler =
                new MFAMethodsCreateHandler(configurationService, mfaMethodsService, dynamoService);
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        when(mfaMethodsService.migrateMfaCredentialsForUser(any())).thenReturn(Optional.empty());
    }

    private static Stream<Arguments> shouldReturn400WhenSmsMigrationFailedArgs() {
        return Stream.of(
                Arguments.of(
                        MfaMigrationFailureReason.NO_USER_FOUND_FOR_EMAIL,
                        ErrorResponse.ERROR_1056));
    }

    @ParameterizedTest
    @MethodSource("shouldReturn400WhenSmsMigrationFailedArgs")
    void shouldReturn400WhenSmsMigrationFailed(
            MfaMigrationFailureReason reason, ErrorResponse expectedError) {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(userProfile.getEmail()).thenReturn(TEST_EMAIL);
        when(mfaMethodsService.migrateMfaCredentialsForUser(any())).thenReturn(Optional.of(reason));

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new SmsMfaDetail(MFAMethodType.SMS, TEST_PHONE_NUMBER),
                        TEST_PUBLIC_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertTrue(result.getBody().contains(String.valueOf(expectedError.getCode())));
        assertTrue(result.getBody().contains(expectedError.getMessage()));
    }

    @Test
    void shouldReturn200AndCreateMfaSmsMfaMethod() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(userProfile.getEmail()).thenReturn(TEST_EMAIL);
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(
                        Either.right(
                                new MfaMethodData(
                                        TEST_SMS_MFA_ID,
                                        PriorityIdentifier.BACKUP,
                                        true,
                                        new SmsMfaDetail(TEST_PHONE_NUMBER))));

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new SmsMfaDetail(TEST_PHONE_NUMBER),
                        TEST_PUBLIC_SUBJECT);

        var result = handler.handleRequest(event, context);

        ArgumentCaptor<MfaMethodCreateOrUpdateRequest.MfaMethod> mfaMethodCaptor =
                ArgumentCaptor.forClass(MfaMethodCreateOrUpdateRequest.MfaMethod.class);

        verify(mfaMethodsService).addBackupMfa(eq(TEST_EMAIL), mfaMethodCaptor.capture());
        var capturedRequest = mfaMethodCaptor.getValue();

        assertEquals(new SmsMfaDetail(TEST_PHONE_NUMBER), capturedRequest.method());
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
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(userProfile.getEmail()).thenReturn(TEST_EMAIL);
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(
                        Either.right(
                                new MfaMethodData(
                                        TEST_AUTH_APP_ID,
                                        PriorityIdentifier.BACKUP,
                                        true,
                                        new AuthAppMfaDetail(TEST_CREDENTIAL))));

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new AuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_PUBLIC_SUBJECT);

        var result = handler.handleRequest(event, context);

        ArgumentCaptor<MfaMethodCreateOrUpdateRequest.MfaMethod> mfaMethodCaptor =
                ArgumentCaptor.forClass(MfaMethodCreateOrUpdateRequest.MfaMethod.class);

        verify(mfaMethodsService).addBackupMfa(eq(TEST_EMAIL), mfaMethodCaptor.capture());
        var capturedRequest = mfaMethodCaptor.getValue();

        assertEquals(new AuthAppMfaDetail(TEST_CREDENTIAL), capturedRequest.method());
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
                        new AuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_PUBLIC_SUBJECT);

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
                        new AuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_PUBLIC_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(404));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));
    }

    @Test
    void shouldReturn400WhenJsonIsInvalid() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new SmsMfaDetail(TEST_PHONE_NUMBER),
                        TEST_PUBLIC_SUBJECT);
        event.setBody("Invalid JSON");
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400WhenMfaMethodServiceReturnsBackupAndDefaultExistError() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new SmsMfaDetail(TEST_PHONE_NUMBER),
                        TEST_PUBLIC_SUBJECT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(
                        Either.left(
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
                        new SmsMfaDetail(TEST_PHONE_NUMBER),
                        TEST_PUBLIC_SUBJECT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(Either.left(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1069));
    }

    @Test
    void shouldReturn400WhenMfaMethodServiceReturnsAuthAppAlreadyExistsError() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new AuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_PUBLIC_SUBJECT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(Either.left(MfaCreateFailureReason.AUTH_APP_EXISTS));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1070));
    }

    @Test
    void shouldReturn500WhenMfaMethodServiceReturnsRetrieveError() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new AuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_PUBLIC_SUBJECT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(Either.left(MfaCreateFailureReason.ERROR_RETRIEVING_MFA_METHODS));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1071));
    }

    private APIGatewayProxyRequestEvent generateApiGatewayEvent(
            PriorityIdentifier priorityIdentifier, MfaDetail mfaDetail, String publicSubject) {

        String body =
                mfaDetail instanceof SmsMfaDetail
                        ? format(
                                """
                                { "mfaMethod": {
                                    "priorityIdentifier": "%s",
                                    "method": {
                                        "mfaMethodType": "SMS",
                                        "phoneNumber": "%s" }
                                    }
                                }
                               """,
                                priorityIdentifier, ((SmsMfaDetail) mfaDetail).phoneNumber())
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
                                priorityIdentifier, ((AuthAppMfaDetail) mfaDetail).credential());

        var event = new APIGatewayProxyRequestEvent();

        event.setPathParameters(Map.of("publicSubjectId", publicSubject));
        event.setBody(body);

        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        event.setRequestContext(proxyRequestContext);
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_ID,
                        ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                        SESSION_ID,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));

        return event;
    }
}
