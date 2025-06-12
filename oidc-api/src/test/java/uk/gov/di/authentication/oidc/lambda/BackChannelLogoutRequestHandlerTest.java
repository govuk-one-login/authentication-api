package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.exceptions.HttpRequestTimeoutException;
import uk.gov.di.authentication.oidc.exceptions.PostRequestFailureException;
import uk.gov.di.authentication.oidc.services.HttpRequestService;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.BackChannelLogoutMessage;
import uk.gov.di.orchestration.shared.helpers.NowHelper.NowClock;
import uk.gov.di.orchestration.shared.services.TokenService;

import java.net.URI;
import java.sql.Date;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static java.time.Clock.fixed;
import static java.time.ZoneId.systemDefault;
import static java.util.Collections.emptyMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.core.Is.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.SqsTestHelper.sqsEventWithPayload;
import static uk.gov.di.orchestration.sharedtest.helper.SqsTestHelper.sqsMessageWithPayload;

class BackChannelLogoutRequestHandlerTest {

    private final OidcAPI oidcApi = mock(OidcAPI.class);
    private final HttpRequestService request = mock(HttpRequestService.class);
    private final TokenService tokenService = mock(TokenService.class);
    private final Context context = mock(Context.class);
    private final Instant fixedDate = Instant.now();

    private final BackChannelLogoutRequestHandler handler =
            new BackChannelLogoutRequestHandler(
                    oidcApi,
                    request,
                    tokenService,
                    new NowClock(fixed(fixedDate, systemDefault())));

    @BeforeEach
    void setup() {
        when(oidcApi.baseURI()).thenReturn(URI.create("https://base-url.account.gov.uk"));
        when(context.getAwsRequestId()).thenReturn("request-id");
    }

    @Test
    void shouldDoNothingIfPayloadIsInvalid() {
        handler.handleRequest(sqsEventWithPayload(null), context);

        verify(tokenService, never())
                .generateSignedJwtUsingExternalKey(any(), eq(Optional.of("logout+jwt")), eq(ES256));
        verify(request, never()).post(any(), any());
    }

    @Test
    void shouldSendRequestToRelyingPartyEndpoint() {
        var input =
                new BackChannelLogoutMessage(
                        "client-id", "https://test.account.gov.uk", "some-subject-id");

        var jwt = mock(SignedJWT.class);

        when(jwt.serialize()).thenReturn("serialized-payload");

        when(tokenService.generateSignedJwtUsingExternalKey(
                        any(JWTClaimsSet.class), eq(Optional.of("logout+jwt")), eq(ES256)))
                .thenReturn(jwt);

        handler.handleRequest(sqsEventWithPayload(input), context);

        verify(request)
                .post(URI.create("https://test.account.gov.uk"), "logout_token=serialized-payload");
    }

    @Test
    void shouldReturnBatchItemFailuresWhenSendRequestFailsWithPostRequestFailureException() {
        var firstInput =
                new BackChannelLogoutMessage(
                        "client-id", "https://test-1.account.gov.uk", "some-subject-id");
        var secondInput =
                new BackChannelLogoutMessage(
                        "client-id", "https://test-2.account.gov.uk", "some-subject-id");

        var jwt = mock(SignedJWT.class);

        when(jwt.serialize()).thenReturn("serialized-payload");

        when(tokenService.generateSignedJwtUsingExternalKey(
                        any(JWTClaimsSet.class), eq(Optional.of("logout+jwt")), eq(ES256)))
                .thenReturn(jwt);

        doThrow(new PostRequestFailureException("Post request failed"))
                .when(request)
                .post(
                        URI.create("https://test-2.account.gov.uk"),
                        "logout_token=serialized-payload");

        var firstMessage = sqsMessageWithPayload(firstInput, "firstMessageId");
        var secondMessage = sqsMessageWithPayload(secondInput, "secondMessageId");
        List<SQSEvent.SQSMessage> messageList = new ArrayList<>();
        firstMessage.ifPresent(messageList::add);
        secondMessage.ifPresent(messageList::add);

        var event = new SQSEvent();
        event.setRecords(messageList);

        var result = handler.handleRequest(event, context);

        List<SQSBatchResponse.BatchItemFailure> batchItemFailures =
                List.of(new SQSBatchResponse.BatchItemFailure("secondMessageId"));

        assertThat(result, is(new SQSBatchResponse(batchItemFailures)));
    }

    @Test
    void shouldReturnBatchItemFailuresWhenSendRequestFailsWithHttpRequestTimeoutException() {
        var firstInput =
                new BackChannelLogoutMessage(
                        "client-id", "https://test-1.account.gov.uk", "some-subject-id");
        var secondInput =
                new BackChannelLogoutMessage(
                        "client-id", "https://test-2.account.gov.uk", "some-subject-id");

        var jwt = mock(SignedJWT.class);

        when(jwt.serialize()).thenReturn("serialized-payload");

        when(tokenService.generateSignedJwtUsingExternalKey(
                        any(JWTClaimsSet.class), eq(Optional.of("logout+jwt")), eq(ES256)))
                .thenReturn(jwt);

        doThrow(new HttpRequestTimeoutException("Request timed out", new Exception()))
                .when(request)
                .post(
                        URI.create("https://test-2.account.gov.uk"),
                        "logout_token=serialized-payload");

        var firstMessage = sqsMessageWithPayload(firstInput, "firstMessageId");
        var secondMessage = sqsMessageWithPayload(secondInput, "secondMessageId");
        List<SQSEvent.SQSMessage> messageList = new ArrayList<>();
        firstMessage.ifPresent(messageList::add);
        secondMessage.ifPresent(messageList::add);

        var event = new SQSEvent();
        event.setRecords(messageList);

        var result = handler.handleRequest(event, context);

        List<SQSBatchResponse.BatchItemFailure> batchItemFailures =
                List.of(new SQSBatchResponse.BatchItemFailure("secondMessageId"));

        assertThat(result, is(new SQSBatchResponse(batchItemFailures)));
    }

    @Test
    void shouldCreateClaimsForBackChannelLogoutMessage() throws ParseException {
        var jwt =
                handler.generateClaims(
                        new BackChannelLogoutMessage(
                                "client-id", "https://test.account.gov.uk", "some-subject-id"));

        assertThat(jwt.getSubject(), is("some-subject-id"));
        assertThat(jwt.getAudience(), is(List.of("client-id")));
        assertThat(jwt.getIssuer(), is("https://base-url.account.gov.uk"));
        assertThat(jwt.getDateClaim("iat"), is(Date.from(fixedDate)));
        assertThat(jwt.getExpirationTime(), is(Date.from(fixedDate.plusSeconds(2 * 60))));
        assertThat(jwt.getJWTID(), isUuid());

        assertThat(
                jwt.getJSONObjectClaim("events"),
                hasEntry("http://schemas.openid.net/event/backchannel-logout", emptyMap()));
    }

    private static Matcher<String> isUuid() {
        return new TypeSafeMatcher<>() {
            @Override
            protected boolean matchesSafely(String item) {
                try {
                    UUID.fromString(item);
                    return true;
                } catch (IllegalArgumentException e) {
                    return false;
                }
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("is a uuid");
            }
        };
    }
}
