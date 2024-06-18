package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.AccountRecoveryResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AccountRecoveryHandlerTest {

    private static final String PERSISTENT_ID = "some-persistent-id-value";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String CLIENT_SESSION_ID = "known-client-session-id";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final DynamoAccountModifiersService dynamoAccountModifiersService =
            mock(DynamoAccountModifiersService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);
    private AccountRecoveryHandler handler;
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

    private final String internalCommonSubjectId =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT_ID.getValue(), "test.account.gov.uk", SALT);
    private final Session session = new Session(IdGenerator.generate()).setEmailAddress(EMAIL);

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
                        clientSessionService,
                        clientService,
                        authenticationService,
                        dynamoAccountModifiersService,
                        auditService);
    }

    @Test
    void shouldNotBePermittedForAccountRecoveryWhenBlockIsPresentAndReturn200() {
        when(dynamoAccountModifiersService.isAccountRecoveryBlockPresent(anyString()))
                .thenReturn(true);
        usingValidSession();
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);

        var event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(IP_ADDRESS));
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL.toUpperCase()));

        var expectedResponse = new AccountRecoveryResponse(false);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(result, hasJsonBody(expectedResponse));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_RECOVERY_NOT_PERMITTED,
                        AuditService.UNKNOWN,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        internalCommonSubjectId,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        PERSISTENT_ID,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)));
    }

    @Test
    void shouldBePermittedForAccountRecoveryWhenNoBlockIsPresentAndReturn200() {
        when(dynamoAccountModifiersService.isAccountRecoveryBlockPresent(anyString()))
                .thenReturn(false);
        usingValidSession();
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);

        var event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(IP_ADDRESS));
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL.toUpperCase()));

        var expectedResponse = new AccountRecoveryResponse(true);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(result, hasJsonBody(expectedResponse));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_RECOVERY_PERMITTED,
                        AuditService.UNKNOWN,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        internalCommonSubjectId,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        PERSISTENT_ID,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)));
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        when(dynamoAccountModifiersService.isAccountRecoveryBlockPresent(anyString()))
                .thenReturn(false);
        usingValidSession();
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);

        var event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(IP_ADDRESS));
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL.toUpperCase()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_RECOVERY_PERMITTED,
                        AuditService.UNKNOWN,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        internalCommonSubjectId,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        PERSISTENT_ID,
                        AuditService.RestrictedSection.empty);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withSubjectID(INTERNAL_SUBJECT_ID.getValue());
    }
}
