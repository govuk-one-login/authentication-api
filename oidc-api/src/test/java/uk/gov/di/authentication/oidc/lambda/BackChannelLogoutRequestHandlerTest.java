package uk.gov.di.authentication.oidc.lambda;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.BackChannelLogoutMessage;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.sql.Date;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static java.time.Clock.fixed;
import static java.time.ZoneId.systemDefault;
import static java.util.Collections.emptyMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BackChannelLogoutRequestHandlerTest {

    private final ConfigurationService configuration = mock(ConfigurationService.class);
    private final Instant fixedDate = Instant.now();

    private final BackChannelLogoutRequestHandler handler =
            new BackChannelLogoutRequestHandler(configuration, fixed(fixedDate, systemDefault()));

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
}
