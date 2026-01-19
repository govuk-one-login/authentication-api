package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class StartPasskeyAssertionHandlerTest {

    private static final UserProfile USER_PROFILE =
            new UserProfile().withEmail(EMAIL).withSubjectID("subject-id");

    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final RelyingParty relyingParty = mock(RelyingParty.class);
    private StartPasskeyAssertionHandler handler;
    private final AuthSessionItem authSession = new AuthSessionItem().withSessionId(SESSION_ID);

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(StartPasskeyAssertionHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(SESSION_ID))));
    }

    @BeforeEach
    void setup() {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(authSessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(authSession));
        handler =
                new StartPasskeyAssertionHandler(
                        configurationService,
                        authenticationService,
                        authSessionService,
                        relyingParty);
    }

    @Nested
    class Success {
        @Test
        void shouldReturn200ForValidRequest() throws Exception {
            authSession.setEmailAddress(EMAIL);
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.of(USER_PROFILE));
            var assertionRequest = createAssertionRequest();
            var expectedJson = assertionRequest.toJson();
            when(relyingParty.startAssertion(any())).thenReturn(assertionRequest);

            var result = handler.handleRequest(startPasskeyAssertionRequest(), context);

            assertThat(result, hasStatus(200));
            assertThat(result.getBody(), equalTo(assertionRequest.toCredentialsGetJson()));
            verify(authSessionService)
                    .updateSession(
                            argThat(
                                    session ->
                                            session.getPasskeyAssertionRequest()
                                                    .equals(expectedJson)));
        }
    }

    @Nested
    class Validation {
        @Test
        void shouldReturn400WhenEmailIsNull() {
            var result = handler.handleRequest(startPasskeyAssertionRequest(), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.EMAIL_ADDRESS_EMPTY));
        }

        @Test
        void shouldReturn400WhenEmailIsEmpty() {
            authSession.setEmailAddress("");

            var result = handler.handleRequest(startPasskeyAssertionRequest(), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.EMAIL_ADDRESS_EMPTY));
        }

        @Test
        void shouldReturn400WhenUserDoesNotExist() {
            authSession.setEmailAddress(EMAIL);
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.empty());

            var result = handler.handleRequest(startPasskeyAssertionRequest(), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.USER_NOT_FOUND));
        }
    }

    @Nested
    class Error {
        @Test
        void shouldReturn500WhenToCredentialsGetJsonSerializationFails() throws Exception {
            authSession.setEmailAddress(EMAIL);
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.of(USER_PROFILE));

            var spyAssertionRequest = spy(createAssertionRequest());
            doThrow(new JsonProcessingException("test") {})
                    .when(spyAssertionRequest)
                    .toCredentialsGetJson();
            when(relyingParty.startAssertion(any())).thenReturn(spyAssertionRequest);

            var result = handler.handleRequest(startPasskeyAssertionRequest(), context);

            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.UNEXPECTED_INTERNAL_API_ERROR));
        }

        @Test
        void shouldReturn500WhenToJsonSerializationFails() throws Exception {
            authSession.setEmailAddress(EMAIL);
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.of(USER_PROFILE));

            var spyAssertionRequest = spy(createAssertionRequest());
            doThrow(new JsonProcessingException("test") {}).when(spyAssertionRequest).toJson();
            when(relyingParty.startAssertion(any())).thenReturn(spyAssertionRequest);

            var result = handler.handleRequest(startPasskeyAssertionRequest(), context);

            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.UNEXPECTED_INTERNAL_API_ERROR));
            verify(authSessionService, never()).updateSession(any());
        }
    }

    private APIGatewayProxyRequestEvent startPasskeyAssertionRequest() {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(VALID_HEADERS)
                .withBody("{}")
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
    }

    private AssertionRequest createAssertionRequest() {
        var challenge = new ByteArray("test-challenge".getBytes(StandardCharsets.UTF_8));
        var publicKeyCredentialRequestOptions =
                PublicKeyCredentialRequestOptions.builder().challenge(challenge).build();
        return AssertionRequest.builder()
                .publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions)
                .build();
    }
}
