package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.BackChannelLogoutMessage;
import uk.gov.di.authentication.oidc.services.HttpRequestService;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.TokenService;

import java.net.URI;
import java.sql.Date;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static java.time.Clock.fixed;
import static java.time.ZoneId.systemDefault;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.core.Is.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.exceptions.Unchecked.unchecked;

class BackChannelLogoutRequestHandlerTest {

    private final ConfigurationService configuration = mock(ConfigurationService.class);
    private final HttpRequestService request = mock(HttpRequestService.class);
    private final TokenService tokenService = mock(TokenService.class);
    private final Instant fixedDate = Instant.now();

    private final BackChannelLogoutRequestHandler handler =
            new BackChannelLogoutRequestHandler(
                    configuration, request, tokenService, fixed(fixedDate, systemDefault()));

    @Test
    void shouldDoNothingIfPayloadIsInvalid() {
        handler.handleRequest(inputEvent(null), null);

        verify(tokenService, never()).generateSignedJWT(any());
        verify(request, never()).post(any(), any());
    }

    @Test
    void shouldSendRequestToRelyingPartyEndpoint() {
        var input =
                new BackChannelLogoutMessage(
                        "client-id", "https://test.account.gov.uk", "some-subject-id");

        var value = stubSignedJwt();

        when(configuration.getOidcApiBaseURL())
                .thenReturn(Optional.of("https://base-url.account.gov.uk"));
        when(tokenService.generateSignedJWT(any(JWTClaimsSet.class))).thenReturn(value);

        handler.handleRequest(inputEvent(input), null);

        verify(request).post(URI.create("https://test.account.gov.uk"), value.toString());
    }

    @Test
    void shouldCreateClaimsForBackChannelLogoutMessage() throws ParseException {
        when(configuration.getOidcApiBaseURL())
                .thenReturn(Optional.of("https://base-url.account.gov.uk"));

        var jwt =
                handler.generateClaims(
                        new BackChannelLogoutMessage(
                                "client-id", "https://test.account.gov.uk", "some-subject-id"));

        assertThat(jwt.getSubject(), is("some-subject-id"));
        assertThat(jwt.getAudience(), is(List.of("client-id")));
        assertThat(jwt.getIssuer(), is("https://base-url.account.gov.uk"));
        assertThat(jwt.getDateClaim("iat"), is(Date.from(fixedDate)));
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

    private SignedJWT stubSignedJwt() {
        return new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), new JWTClaimsSet.Builder().build());
    }

    private SQSEvent inputEvent(BackChannelLogoutMessage payload) {
        var messages =
                Optional.ofNullable(payload)
                        .map(unchecked(ObjectMapperFactory.getInstance()::writeValueAsString))
                        .map(
                                body -> {
                                    var message = new SQSEvent.SQSMessage();
                                    message.setBody(body);

                                    return message;
                                })
                        .map(List::of)
                        .orElse(emptyList());

        var event = new SQSEvent();
        event.setRecords(messages);

        return event;
    }
}
