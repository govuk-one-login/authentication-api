package uk.gov.di.accountmanagement.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_DELETE_ACCOUNT;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class AccountDeletionServiceTest {
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDeleteService dynamoDeleteService = mock(DynamoDeleteService.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final APIGatewayProxyRequestEvent input = mock(APIGatewayProxyRequestEvent.class);
    private final APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
            mock(APIGatewayProxyRequestEvent.ProxyRequestContext.class);
    private static final MockedStatic<ClientSessionIdHelper> clientSessionIdHelperMockedStatic =
            Mockito.mockStatic(ClientSessionIdHelper.class);
    private static final MockedStatic<PersistentIdHelper> persistentSessionIdHelperMockedStatic =
            Mockito.mockStatic(PersistentIdHelper.class);
    private static final MockedStatic<IpAddressHelper> ipAddressHelperMockedStatic =
            Mockito.mockStatic(IpAddressHelper.class);
    private final AccountDeletionService underTest =
            new AccountDeletionService(
                    authenticationService,
                    sqsClient,
                    auditService,
                    configurationService,
                    dynamoDeleteService);
    private static final String TEST_CLIENT_SESSION_ID = "test-client-session-id";
    private static final Map<String, String> TEST_HEADERS = Map.of("test-header", "test-header");
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final Object testClientIdObject = mock(Object.class);
    private static final Map<String, Object> TEST_AUTHORIZER =
            Map.of("clientId", testClientIdObject);
    private static final String SUBJECT_ID = new Subject().getValue();
    private static final String TEST_PERSISTENT_SESSION_ID = "test-persistent-session-id";
    private static final String TEST_IP_ADDRESS = "test-ip-address";

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AccountDeletionService.class);

    @BeforeEach
    public void setup() {
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(authenticationService.getOrGenerateSalt(any())).thenReturn(new byte[0xaa]);
    }

    @AfterAll
    static void afterAll() {
        if (clientSessionIdHelperMockedStatic != null) {
            clientSessionIdHelperMockedStatic.close();
        }
        if (persistentSessionIdHelperMockedStatic != null) {
            persistentSessionIdHelperMockedStatic.close();
        }
        if (ipAddressHelperMockedStatic != null) {
            ipAddressHelperMockedStatic.close();
        }
    }

    @Test
    void removeAccountCallsDeleteAccount() throws Json.JsonException {
        // given
        var expectedEmail = "test@example.com";
        when(userProfile.getEmail()).thenReturn(expectedEmail);
        when(userProfile.getSubjectID()).thenReturn(new Subject().getValue());
        // when
        underTest.removeAccount(
                Optional.of(input),
                userProfile,
                Optional.empty(),
                AccountDeletionReason.USER_INITIATED);
        // then
        verify(dynamoDeleteService).deleteAccount(eq(expectedEmail), any());
    }

    @Test
    void removeAccountThrowsIfDeleteAccountFails() {
        // given
        var expectedException = new RuntimeException();
        when(userProfile.getEmail()).thenReturn("test@example.com");
        when(userProfile.getSubjectID()).thenReturn(new Subject().getValue());
        doThrow(expectedException).when(dynamoDeleteService).deleteAccount(any(), any());

        // then
        assertThrows(
                expectedException.getClass(),
                () ->
                        underTest.removeAccount(
                                Optional.of(input),
                                userProfile,
                                Optional.empty(),
                                AccountDeletionReason.USER_INITIATED));
    }

    @Test
    void removeAccountSendsNotificationEmail() throws Json.JsonException {
        // given
        var expectedEmail = "test@example.com";
        when(userProfile.getEmail()).thenReturn(expectedEmail);
        when(userProfile.getSubjectID()).thenReturn(new Subject().getValue());

        // when
        underTest.removeAccount(
                Optional.of(input),
                userProfile,
                Optional.empty(),
                AccountDeletionReason.USER_INITIATED);

        // then
        var captor = ArgumentCaptor.forClass(String.class);
        verify(sqsClient).send(captor.capture());
        var notifyRequest =
                SerializationService.getInstance().readValue(captor.getValue(), HashMap.class);
        assertEquals(expectedEmail, notifyRequest.get("destination"));
        assertEquals("DELETE_ACCOUNT", notifyRequest.get("notificationType"));
        assertEquals("EN", notifyRequest.get("language"));
    }

    @Test
    void removeAccountSucceedsIfEmailNotificationFails() {
        // given
        when(userProfile.getEmail()).thenReturn("test@example.com");
        when(userProfile.getSubjectID()).thenReturn(new Subject().getValue());
        doThrow(new RuntimeException()).when(sqsClient).send(any());

        // then
        assertDoesNotThrow(
                () ->
                        underTest.removeAccount(
                                Optional.of(input),
                                userProfile,
                                Optional.empty(),
                                AccountDeletionReason.USER_INITIATED));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Failed to send account deletion email")));
    }

    @EnumSource()
    @ParameterizedTest
    void removeAccountAudits(AccountDeletionReason reason) throws Json.JsonException {
        // given
        var expectedEmail = "test@example.com";
        var expectedPhoneNumber = "+44123456789";
        when(userProfile.getEmail()).thenReturn(expectedEmail);
        when(userProfile.getPhoneNumber()).thenReturn(expectedPhoneNumber);
        when(userProfile.getSubjectID()).thenReturn(SUBJECT_ID);
        when(input.getHeaders()).thenReturn(TEST_HEADERS);
        clientSessionIdHelperMockedStatic
                .when(() -> ClientSessionIdHelper.extractSessionIdFromHeaders(TEST_HEADERS))
                .thenReturn(TEST_CLIENT_SESSION_ID);
        when(input.getRequestContext()).thenReturn(proxyRequestContext);
        when(proxyRequestContext.getAuthorizer()).thenReturn(TEST_AUTHORIZER);
        when(testClientIdObject.toString()).thenReturn(TEST_CLIENT_ID);
        persistentSessionIdHelperMockedStatic
                .when(() -> PersistentIdHelper.extractPersistentIdFromHeaders(TEST_HEADERS))
                .thenReturn(TEST_PERSISTENT_SESSION_ID);
        ipAddressHelperMockedStatic
                .when(() -> IpAddressHelper.extractIpAddress(input))
                .thenReturn(TEST_IP_ADDRESS);

        // when
        underTest.removeAccount(Optional.of(input), userProfile, Optional.empty(), reason);

        // then
        verify(auditService)
                .submitAuditEvent(
                        eq(AUTH_DELETE_ACCOUNT),
                        argThat(
                                auditContext ->
                                        Objects.equals(auditContext.clientId(), TEST_CLIENT_ID)
                                                && Objects.equals(
                                                        auditContext.clientSessionId(),
                                                        TEST_CLIENT_SESSION_ID)
                                                && Objects.equals(
                                                        auditContext.email(), expectedEmail)
                                                && Objects.equals(
                                                        auditContext.phoneNumber(),
                                                        expectedPhoneNumber)
                                                && Objects.equals(
                                                        auditContext.ipAddress(), TEST_IP_ADDRESS)
                                                && Objects.equals(
                                                        auditContext.persistentSessionId(),
                                                        TEST_PERSISTENT_SESSION_ID)),
                        eq(pair("account_deletion_reason", reason)));
    }

    @Test
    void removeAccountSucceedsIfAuditingFails() {
        // given
        when(userProfile.getEmail()).thenReturn("test@example.com");
        when(userProfile.getSubjectID()).thenReturn(new Subject().getValue());
        doThrow(new RuntimeException()).when(auditService).submitAuditEvent(any(), any());
        // then
        assertDoesNotThrow(
                () ->
                        underTest.removeAccount(
                                Optional.of(input),
                                userProfile,
                                Optional.empty(),
                                AccountDeletionReason.USER_INITIATED));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Failed to audit account deletion")));
    }
}
