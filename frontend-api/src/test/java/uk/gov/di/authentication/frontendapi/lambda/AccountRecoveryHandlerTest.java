package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_NOT_PERMITTED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_PERMITTED;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AccountRecoveryHandlerTest {

    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoAccountModifiersService dynamoAccountModifiersService =
            mock(DynamoAccountModifiersService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private AccountRecoveryHandler handler;

    private final String internalCommonSubjectId =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT_ID.getValue(), "test.account.gov.uk", SALT);
    private final Session session = new Session();
    private final AuthSessionItem authSession =
            new AuthSessionItem().withSessionId(SESSION_ID).withClientId(AuditService.UNKNOWN);

    private final AuditContext auditContext =
            new AuditContext(
                    AuditService.UNKNOWN,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    internalCommonSubjectId,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));

    @BeforeEach
    void setup() {
        var userProfile = generateUserProfile();
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(SALT);
        when(authenticationService.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(userProfile));
        handler =
                new AccountRecoveryHandler(
                        configurationService,
                        sessionService,
                        clientService,
                        authenticationService,
                        dynamoAccountModifiersService,
                        auditService,
                        authSessionService);
    }

    @Test
    void shouldNotBePermittedForAccountRecoveryWhenBlockIsPresentAndReturn200() {
        when(dynamoAccountModifiersService.isAccountRecoveryBlockPresent(anyString()))
                .thenReturn(true);
        usingValidSession();

        var body = format("{ \"email\": \"%s\" }", EMAIL.toUpperCase());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody("{\"accountRecoveryPermitted\":false}"));
        verify(auditService).submitAuditEvent(AUTH_ACCOUNT_RECOVERY_NOT_PERMITTED, auditContext);
    }

    @Test
    void shouldBePermittedForAccountRecoveryWhenNoBlockIsPresentAndReturn200() {
        when(dynamoAccountModifiersService.isAccountRecoveryBlockPresent(anyString()))
                .thenReturn(false);
        usingValidSession();

        var body = format("{ \"email\": \"%s\" }", EMAIL.toUpperCase());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody("{\"accountRecoveryPermitted\":true}"));
        verify(auditService).submitAuditEvent(AUTH_ACCOUNT_RECOVERY_PERMITTED, auditContext);
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        when(dynamoAccountModifiersService.isAccountRecoveryBlockPresent(anyString()))
                .thenReturn(false);
        usingValidSession();

        var body = format("{ \"email\": \"%s\" }", EMAIL.toUpperCase());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS_WITHOUT_AUDIT_ENCODED, body);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_RECOVERY_PERMITTED,
                        auditContext.withTxmaAuditEncoded(Optional.empty()));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withSubjectID(INTERNAL_SUBJECT_ID.getValue());
    }
}
