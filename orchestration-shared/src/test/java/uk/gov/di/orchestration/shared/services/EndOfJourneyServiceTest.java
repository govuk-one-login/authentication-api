package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AccountInterventionState;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;

import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EndOfJourneyServiceTest {
    private static final AccountIntervention NO_INTERVENTION =
            new AccountIntervention(new AccountInterventionState(false, false, false, false));
    private static final AccountIntervention BLOCKED_INTERVENTION =
            new AccountIntervention(new AccountInterventionState(true, false, false, false));
    private static final AccountIntervention SUSPENDED_NO_ACTION =
            new AccountIntervention(new AccountInterventionState(false, true, false, false));
    private static final AccountIntervention SUSPENDED_WITH_REPROVE_IDENTITY =
            new AccountIntervention(new AccountInterventionState(false, true, true, false));
    private static final String SESSION_ID = "a-session-id";
    private static final String TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER =
            "urn:fdc:gov.uk:2022:0VzHWj9aaJpyHXJX8B5QJ-UOUibweHmkSg1GjF6w9yM";
    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_SESSION_ID = "test-csid";
    private static final String EMAIL = "test@email.com";
    private static final Long AUTH_TIME = 123456L;
    private static final String ERROR_PAGE_URI = "http://test.com/error";
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AccountInterventionService accountInterventionService =
            mock(AccountInterventionService.class);
    private final LogoutService logoutService = mock(LogoutService.class);
    private final OrchAuthCodeService orchAuthCodeService = mock(OrchAuthCodeService.class);
    private final AuditContext auditContext = mock(AuditContext.class);
    private final TxmaAuditUser auditUser = mock(TxmaAuditUser.class);
    private final OrchSessionItem orchSession =
            new OrchSessionItem(SESSION_ID)
                    .withInternalCommonSubjectId(TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER)
                    .withAuthTime(AUTH_TIME);
    private EndOfJourneyService service;

    @BeforeEach
    void setup() {
        when(logoutService.handleAccountInterventionLogout(
                        new DestroySessionsRequest(SESSION_ID, orchSession),
                        auditUser,
                        CLIENT_ID,
                        BLOCKED_INTERVENTION))
                .thenReturn(RedirectService.redirectToFrontendErrorPage(ERROR_PAGE_URI));
        when(logoutService.handleAccountInterventionLogout(
                        new DestroySessionsRequest(SESSION_ID, orchSession),
                        auditUser,
                        CLIENT_ID,
                        SUSPENDED_NO_ACTION))
                .thenReturn(RedirectService.redirectToFrontendErrorPage(ERROR_PAGE_URI));
        when(configurationService.isAccountInterventionServiceActionEnabled()).thenReturn(true);
        when(orchAuthCodeService.generateAndSaveAuthorisationCode(
                        CLIENT_ID,
                        CLIENT_SESSION_ID,
                        EMAIL,
                        AUTH_TIME,
                        TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER))
                .thenReturn(AUTH_CODE);
        orchSession.addClientSession(CLIENT_SESSION_ID);
        service =
                new EndOfJourneyService(
                        configurationService,
                        accountInterventionService,
                        logoutService,
                        orchAuthCodeService);
    }

    @Nested
    class HandleAccountInterventions {

        @Test
        void shouldRedirectAndLogoutWhenAISReturnsBlocked() {
            var response =
                    service.checkForIntervention(
                            orchSession, BLOCKED_INTERVENTION, auditUser, CLIENT_ID, true);

            assertTrue(response.isPresent());
            assertThat(response.get().getHeaders().get("Location"), equalTo(ERROR_PAGE_URI));
        }

        @Test
        void shouldRedirectAndLogoutWhenAISReturnsSuspended() {
            var response =
                    service.checkForIntervention(
                            orchSession, SUSPENDED_NO_ACTION, auditUser, CLIENT_ID, true);

            assertTrue(response.isPresent());
            assertThat(response.get().getHeaders().get("Location"), equalTo(ERROR_PAGE_URI));
        }

        @Test
        void shouldNotRedirectAndLogoutIfAISReturnsNoInterventions() {
            var response =
                    service.checkForIntervention(
                            orchSession, NO_INTERVENTION, auditUser, CLIENT_ID, true);

            assertTrue(response.isEmpty());
        }

        @Test
        void shouldNotRedirectAndLogoutIfAISReturnsSuspendedWithReproveWhenOnAuthOnlyJourney() {
            var response =
                    service.checkForIntervention(
                            orchSession,
                            SUSPENDED_WITH_REPROVE_IDENTITY,
                            auditUser,
                            CLIENT_ID,
                            true);

            assertTrue(response.isEmpty());
        }

        @Test
        void shouldNotRedirectAndLogoutIfAISIsDisabled() {
            when(configurationService.isAccountInterventionServiceActionEnabled())
                    .thenReturn(false);

            var response =
                    service.checkForIntervention(
                            orchSession, BLOCKED_INTERVENTION, auditUser, CLIENT_ID, true);

            assertTrue(response.isEmpty());
        }

        @Test
        void shouldGetInterventionFromAISServiceThenRedirect() {
            when(accountInterventionService.getAccountIntervention(
                            TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER, auditContext))
                    .thenReturn(BLOCKED_INTERVENTION);

            var response =
                    service.getAndCheckForIntervention(
                            orchSession, auditContext, auditUser, CLIENT_ID, true);

            assertTrue(response.isPresent());
            assertThat(response.get().getHeaders().get("Location"), equalTo(ERROR_PAGE_URI));
        }
    }

    @Nested
    class GenerateAuthResponse {
        private final State state = new State();
        private final Nonce nonce = new Nonce();
        private final URI redirectUri = URI.create("http://rp-url/redirect");
        private final ResponseMode responseMode = ResponseMode.QUERY;
        private final AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                Scope.parse("openid"),
                                new ClientID(CLIENT_ID),
                                redirectUri)
                        .state(state)
                        .nonce(nonce)
                        .responseMode(responseMode)
                        .build();

        @Test
        void shouldGenerateAuthCodeAndCreateSuccessfulAuthResponse() {
            var response =
                    service.generateSuccessfulAuthResponse(
                            authRequest, CLIENT_ID, CLIENT_SESSION_ID, EMAIL, orchSession);

            verify(orchAuthCodeService)
                    .generateAndSaveAuthorisationCode(
                            CLIENT_ID,
                            CLIENT_SESSION_ID,
                            EMAIL,
                            AUTH_TIME,
                            TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER);
            assertThat(response.getRedirectionURI(), equalTo(redirectUri));
            assertThat(response.getAuthorizationCode(), equalTo(AUTH_CODE));
            assertThat(response.getState(), equalTo(state));
            assertThat(response.getResponseMode(), equalTo(responseMode));
        }

        @Test
        void shouldCreateAuthResponseWithError() {
            var error = new ErrorObject("test_error", "Test Description");
            var response = service.generateAuthenticationErrorResponse(authRequest, error);
            var expectedUri =
                    redirectUri
                            + "?error=test_error"
                            + "&error_description=Test+Description"
                            + "&state="
                            + state;
            assertThat(response.getStatusCode(), equalTo(302));
            assertThat(response.getHeaders().get("Location"), equalTo(expectedUri));
        }
    }
}
