package uk.gov.di.accountmanagement.services;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AccountDataScope;
import uk.gov.di.authentication.shared.entity.JwtFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AccessTokenConstructorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InactiveAccountDeletionTokenServiceTest {

    private static final String PUBLIC_SUBJECT_ID = "urn:fdc:gov.uk:2022:abc123";
    private static final String AUDIENCE = "https://account.test.account.gov.uk";
    private static final String ISSUER = "https://signin.test.account.gov.uk";
    private static final String CLIENT_ID = "inactive-account-deletion";
    private static final String SIGNING_KEY = "test-signing-key-id";

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AccessTokenConstructorService accessTokenConstructorService =
            mock(AccessTokenConstructorService.class);
    private final Clock fixedClock =
            Clock.fixed(Instant.parse("2026-08-17T12:00:00Z"), ZoneId.of("UTC"));
    private final NowHelper.NowClock nowClock = new NowHelper.NowClock(fixedClock);

    private InactiveAccountDeletionTokenService tokenService;

    @BeforeEach
    void setUp() {
        when(configurationService.getAuthToAccountDataApiAudience()).thenReturn(AUDIENCE);
        when(configurationService.getAuthIssuerClaim()).thenReturn(ISSUER);
        when(configurationService.getInactiveAccountDeletionClientId()).thenReturn(CLIENT_ID);
        when(configurationService.getAuthToAccountDataSigningKey()).thenReturn(SIGNING_KEY);

        tokenService =
                new InactiveAccountDeletionTokenService(
                        configurationService, accessTokenConstructorService, nowClock);
    }

    @Test
    void shouldCreateAccessTokenWithCorrectParameters() {
        var expectedToken = new BearerAccessToken("test-token-value");
        when(accessTokenConstructorService.createSignedAccessToken(
                        any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Result.success(expectedToken));

        var result = tokenService.createAccountDataApiAccessToken(PUBLIC_SUBJECT_ID);

        assertTrue(result.isSuccess());
        assertEquals(expectedToken, result.getSuccess());

        var expectedIssueTime = Date.from(fixedClock.instant());

        verify(accessTokenConstructorService)
                .createSignedAccessToken(
                        eq(PUBLIC_SUBJECT_ID),
                        eq(List.of(AccountDataScope.ACCOUNT_DELETE)),
                        eq(expectedIssueTime),
                        any(Date.class),
                        eq(AUDIENCE),
                        eq(ISSUER),
                        eq(CLIENT_ID),
                        eq(SIGNING_KEY));
    }

    @Test
    void shouldReturnFailureWhenTokenCreationFails() {
        when(accessTokenConstructorService.createSignedAccessToken(
                        any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Result.failure(JwtFailureReason.SIGNING_ERROR));

        var result = tokenService.createAccountDataApiAccessToken(PUBLIC_SUBJECT_ID);

        assertTrue(result.isFailure());
        assertEquals(JwtFailureReason.SIGNING_ERROR, result.getFailure());
    }
}
