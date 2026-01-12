package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.AMCScope;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AMCAuthorizationServiceTest {
    private AMCAuthorizationService amcAuthorizationService;
    private static final String INTERNAL_PAIRWISE_ID =
            "urn:fdc:gov.uk:2022:xH7hrtJCgdi2NEF7TXcOC6SMz8DohdoLo9hWqQMWPRk";
    private static final String AUTH_ISSUER_CLAIM = "https://signin.account.gov.uk/";
    private static final String AUTH_TO_AUTH_AUDIENCE = "https://api.manage.account.gov.uk";
    private static final String CLIENT_ID = "test-client-id";
    private static final String SESSION_ID = "test-session-id";
    private static final AuthSessionItem authSessionItem = mock(AuthSessionItem.class);
    private static final Date NOW =
            new Date(System.currentTimeMillis() + (20L * 365 * 24 * 60 * 60 * 1000));
    private static final long SESSION_EXPIRY = 300L;

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final NowHelper.NowClock nowClock = mock(NowHelper.NowClock.class);

    @BeforeEach
    void setup() {
        amcAuthorizationService = new AMCAuthorizationService(configurationService, nowClock);
    }

    @Test
    void shouldReturnJWTClaimsForAccessToken() {
        when(configurationService.getAuthIssuerClaim()).thenReturn(AUTH_ISSUER_CLAIM);
        when(configurationService.getAuthToAuthAudience()).thenReturn(AUTH_TO_AUTH_AUDIENCE);
        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        when(nowClock.now()).thenReturn(NOW);
        when(nowClock.nowPlus(SESSION_EXPIRY, ChronoUnit.SECONDS))
                .thenReturn(new Date(NOW.getTime() + 300_000));
        when(authSessionItem.getClientId()).thenReturn(CLIENT_ID);
        when(authSessionItem.getSessionId()).thenReturn(SESSION_ID);

        JWTClaimsSet result =
                amcAuthorizationService.createAccessTokenClaims(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem);

        assertEquals(List.of(AMCScope.ACCOUNT_DELETE.getValue()), result.getClaim("scope"));
        assertEquals(AUTH_ISSUER_CLAIM, result.getIssuer());
        assertEquals(List.of(AUTH_TO_AUTH_AUDIENCE), result.getAudience());
        assertEquals(INTERNAL_PAIRWISE_ID, result.getSubject());
        assertEquals(CLIENT_ID, result.getClaim("client_id"));
        assertEquals(SESSION_ID, result.getClaim("sid"));
        assertDoesNotThrow(() -> UUID.fromString(result.getJWTID()));
        assertEquals(NOW, result.getIssueTime());
        assertEquals(NOW, result.getNotBeforeTime());
        assertEquals(new Date(NOW.getTime() + 300_000), result.getExpirationTime());
    }
}
