package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.authentication.auditevents.entity.AuthPasskeyDeleteSuccessful;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.passkeys.PasskeysRetrieveResponse;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AccountDataApiService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.PASSKEY_DELETED_NONE_REMAINING;
import static uk.gov.di.accountmanagement.entity.NotificationType.PASSKEY_DELETED_SOME_REMAINING;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class PasskeysDeleteProxyHandlerTest {
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AccountDataApiService accountDataApiService = mock(AccountDataApiService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final StructuredAuditService structuredAuditService =
            mock(StructuredAuditService.class);

    private static final String ADAPI_TOKEN_HEADER = "X-ADAPI-AccessToken";
    private static final String TOKEN = "token";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";

    private PasskeysDeleteProxyHandler handler;

    @BeforeEach
    void setUp() {
        var userProfile =
                new UserProfile().withSubjectID(PUBLIC_SUBJECT_ID).withEmail(TEST_EMAIL_ADDRESS);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(any(UserProfile.class)))
                .thenReturn("test-salt".getBytes(StandardCharsets.UTF_8));
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");

        handler =
                new PasskeysDeleteProxyHandler(
                        configurationService,
                        accountDataApiService,
                        sqsClient,
                        dynamoService,
                        auditService,
                        structuredAuditService);
    }

    private static final String PASSKEY_IDENTIFIER = "test-passkey-id";
    private static final String OTHER_PASSKEY_IDENTIFIER = "other-test-passkey-id";

    @Nested
    class SuccessfulRequest {
        @Test
        void shouldProxyResponseFromService()
                throws UnsuccessfulAccountDataApiResponseException, Json.JsonException {
            // Arrange
            var mockHttpResponse = mock(HttpResponse.class);
            when(accountDataApiService.retrievePasskeys(PUBLIC_SUBJECT_ID, TOKEN))
                    .thenReturn(
                            new PasskeysRetrieveResponse(
                                    List.of(aPasskeyResponse(PASSKEY_IDENTIFIER))));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn("{\"deleted\": true}");
            when(accountDataApiService.deletePasskey(PUBLIC_SUBJECT_ID, PASSKEY_IDENTIFIER, TOKEN))
                    .thenReturn(mockHttpResponse);

            // Act
            var result = handler.handleRequest(passkeysDeleteProxyRequest(), context);

            // Assert
            assertThat(result, hasStatus(200));
            assertThat(result, hasBody("{\"deleted\": true}"));
            verify(accountDataApiService)
                    .deletePasskey(PUBLIC_SUBJECT_ID, PASSKEY_IDENTIFIER, TOKEN);
        }

        private static Stream<Arguments> expectedNotificationTypeForUserPasskeys() {
            return Stream.of(
                    Arguments.of(
                            List.of(aPasskeyResponse(PASSKEY_IDENTIFIER)),
                            PASSKEY_DELETED_NONE_REMAINING),
                    Arguments.of(
                            List.of(
                                    aPasskeyResponse(PASSKEY_IDENTIFIER),
                                    aPasskeyResponse(OTHER_PASSKEY_IDENTIFIER)),
                            PASSKEY_DELETED_SOME_REMAINING));
        }

        @ParameterizedTest
        @MethodSource("expectedNotificationTypeForUserPasskeys")
        void shouldRetrievePasskeyCountAndSendCorrectNotification(
                List<PasskeysRetrieveResponse.PasskeyResponse> userPasskeys,
                NotificationType expectedNotificationType)
                throws UnsuccessfulAccountDataApiResponseException, Json.JsonException {
            // Arrange
            var mockHttpResponse = mock(HttpResponse.class);
            when(accountDataApiService.retrievePasskeys(PUBLIC_SUBJECT_ID, TOKEN))
                    .thenReturn(new PasskeysRetrieveResponse(userPasskeys));
            when(mockHttpResponse.statusCode()).thenReturn(204);
            when(mockHttpResponse.body()).thenReturn("");
            when(accountDataApiService.deletePasskey(PUBLIC_SUBJECT_ID, PASSKEY_IDENTIFIER, TOKEN))
                    .thenReturn(mockHttpResponse);

            // Act
            handler.handleRequest(passkeysDeleteProxyRequest(), context);

            // Assert
            var sqsMessageCaptor = ArgumentCaptor.forClass(String.class);
            verify(sqsClient).send(sqsMessageCaptor.capture());

            var sentNotifyRequest =
                    SerializationService.getInstance()
                            .readValue(sqsMessageCaptor.getValue(), NotifyRequest.class);
            assertThat(sentNotifyRequest.getDestination(), equalTo(TEST_EMAIL_ADDRESS));
            assertThat(sentNotifyRequest.getNotificationType(), equalTo(expectedNotificationType));
            assertThat(sentNotifyRequest.getLanguage(), equalTo(SupportedLanguage.EN));
        }

        @Test
        void shouldEmitSuccessAuditEventOnSuccessfulDeletion()
                throws UnsuccessfulAccountDataApiResponseException, Json.JsonException {
            // Arrange
            var mockHttpResponse = mock(HttpResponse.class);
            when(accountDataApiService.retrievePasskeys(PUBLIC_SUBJECT_ID, TOKEN))
                    .thenReturn(
                            new PasskeysRetrieveResponse(
                                    List.of(
                                            aPasskeyResponse(PASSKEY_IDENTIFIER),
                                            aPasskeyResponse(OTHER_PASSKEY_IDENTIFIER))));
            when(mockHttpResponse.statusCode()).thenReturn(204);
            when(mockHttpResponse.body()).thenReturn("");
            when(accountDataApiService.deletePasskey(PUBLIC_SUBJECT_ID, PASSKEY_IDENTIFIER, TOKEN))
                    .thenReturn(mockHttpResponse);

            // Act
            handler.handleRequest(passkeysDeleteProxyRequest(), context);

            // Assert

            ArgumentCaptor<AuthPasskeyDeleteSuccessful> auditEventCaptor =
                    ArgumentCaptor.forClass(AuthPasskeyDeleteSuccessful.class);
            verify(structuredAuditService).submitAuditEvent(auditEventCaptor.capture());
            var submittedAuditEvent = auditEventCaptor.getValue();

            assertEquals("AUTH_PASSKEY_DELETE_SUCCESSFUL", submittedAuditEvent.eventName());
            assertEquals(1, submittedAuditEvent.user().passkeyCount());
            assertEquals(
                    PASSKEY_IDENTIFIER,
                    submittedAuditEvent.restricted().passkey().passkeyCredentialId());
        }
    }

    @Nested
    class FailedRequest {
        @Test
        void shouldReturn500IfServiceThrowsException()
                throws UnsuccessfulAccountDataApiResponseException, Json.JsonException {
            // Arrange
            when(accountDataApiService.retrievePasskeys(PUBLIC_SUBJECT_ID, TOKEN))
                    .thenReturn(
                            new PasskeysRetrieveResponse(
                                    List.of(aPasskeyResponse(PASSKEY_IDENTIFIER))));
            when(accountDataApiService.deletePasskey(PUBLIC_SUBJECT_ID, PASSKEY_IDENTIFIER, TOKEN))
                    .thenThrow(new UnsuccessfulAccountDataApiResponseException("service error", 0));

            // Act
            var result = handler.handleRequest(passkeysDeleteProxyRequest(), context);

            // Assert
            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.INTERNAL_SERVER_ERROR));
            verify(accountDataApiService)
                    .deletePasskey(PUBLIC_SUBJECT_ID, PASSKEY_IDENTIFIER, TOKEN);
        }
    }

    private APIGatewayProxyRequestEvent passkeysDeleteProxyRequest() {
        var headersWithToken = new HashMap<>(VALID_HEADERS);
        headersWithToken.put(ADAPI_TOKEN_HEADER, TOKEN);

        var requestContext = contextWithSourceIp(IP_ADDRESS);
        requestContext.setAuthorizer(Map.of("clientId", "test-client-id"));

        return new APIGatewayProxyRequestEvent()
                .withPathParameters(
                        Map.of(
                                "publicSubjectId", PUBLIC_SUBJECT_ID,
                                "passkeyIdentifier", PASSKEY_IDENTIFIER))
                .withHeaders(headersWithToken)
                .withRequestContext(requestContext);
    }

    private static PasskeysRetrieveResponse.PasskeyResponse aPasskeyResponse(String passkeyId) {
        return new PasskeysRetrieveResponse.PasskeyResponse(
                passkeyId,
                "cHVibGljLWtleS1jb3Nl",
                "some-aaguid",
                true,
                5,
                List.of(),
                true,
                true,
                true,
                "some-timestamp",
                "another-timestamp");
    }
}
