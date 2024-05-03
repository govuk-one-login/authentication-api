package uk.gov.di.accountmanagement.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.DELETE_ACCOUNT;
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

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AccountDeletionService.class);

    @BeforeEach
    public void setup() {
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(authenticationService.getOrGenerateSalt(any())).thenReturn(new byte[0xaa]);
    }

    @ParameterizedTest
    @MethodSource("identifiersSource")
    void removeAccountReturnsCorrectIdentifiers(
            String expectedPublicSubjectId,
            String expectedLegacySubjectId,
            String expectedSubjectId)
            throws Json.JsonException {
        // given
        when(userProfile.getPublicSubjectID()).thenReturn(expectedPublicSubjectId);
        when(userProfile.getLegacySubjectID()).thenReturn(expectedLegacySubjectId);
        when(userProfile.getSubjectID()).thenReturn(expectedSubjectId);

        // when
        var deletedAccountIdentifiers = underTest.removeAccount(Optional.of(input), userProfile);

        // then
        assertEquals(expectedPublicSubjectId, deletedAccountIdentifiers.publicSubjectId());
        assertEquals(expectedLegacySubjectId, deletedAccountIdentifiers.legacySubjectId());
        assertEquals(expectedSubjectId, deletedAccountIdentifiers.subjectId());
    }

    private static Stream<Arguments> identifiersSource() {
        var publicSubjectId = new Subject().getValue();
        var legacySubjectId = new Subject().getValue();
        var subjectId = new Subject().getValue();

        return Stream.of(
                Arguments.of(publicSubjectId, legacySubjectId, subjectId),
                Arguments.of(publicSubjectId, null, subjectId),
                Arguments.of(null, legacySubjectId, subjectId),
                Arguments.of(null, null, subjectId));
    }

    @Test
    void removeAccountCallsDeleteAccount() throws Json.JsonException {
        // given
        var expectedEmail = "test@example.com";
        when(userProfile.getEmail()).thenReturn(expectedEmail);
        when(userProfile.getSubjectID()).thenReturn(new Subject().getValue());
        // when
        underTest.removeAccount(Optional.of(input), userProfile);
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
                () -> underTest.removeAccount(Optional.of(input), userProfile));
    }

    @Test
    void removeAccountSendsNotificationEmail() throws Json.JsonException {
        // given
        var expectedEmail = "test@example.com";
        when(userProfile.getEmail()).thenReturn(expectedEmail);
        when(userProfile.getSubjectID()).thenReturn(new Subject().getValue());

        // when
        underTest.removeAccount(Optional.of(input), userProfile);

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
        assertDoesNotThrow(() -> underTest.removeAccount(Optional.of(input), userProfile));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Failed to send account deletion email")));
    }

    @Test
    void removeAccountAudits() throws Json.JsonException {
        // given
        var expectedEmail = "test@example.com";
        var expectedPhoneNumber = "+44123456789";
        when(userProfile.getEmail()).thenReturn(expectedEmail);
        when(userProfile.getPhoneNumber()).thenReturn(expectedPhoneNumber);
        when(userProfile.getSubjectID()).thenReturn(new Subject().getValue());
        when(input.getHeaders()).thenReturn(TEST_HEADERS);
        clientSessionIdHelperMockedStatic
                .when(() -> ClientSessionIdHelper.extractSessionIdFromHeaders(TEST_HEADERS))
                .thenReturn(TEST_CLIENT_SESSION_ID);
        when(input.getRequestContext()).thenReturn(proxyRequestContext);
        when(proxyRequestContext.getAuthorizer()).thenReturn(TEST_AUTHORIZER);
        when(testClientIdObject.toString()).thenReturn(TEST_CLIENT_ID);

        // when
        underTest.removeAccount(Optional.of(input), userProfile);

        // then
        verify(auditService)
                .submitAuditEvent(
                        eq(DELETE_ACCOUNT),
                        eq(TEST_CLIENT_ID),
                        eq(TEST_CLIENT_SESSION_ID),
                        eq(AuditService.UNKNOWN),
                        anyString(),
                        eq(expectedEmail),
                        eq(AuditService.UNKNOWN),
                        eq(expectedPhoneNumber),
                        eq(AuditService.UNKNOWN));
    }

    @Test
    void removeAccountSucceedsIfAuditingFails() {
        // given
        when(userProfile.getEmail()).thenReturn("test@example.com");
        when(userProfile.getSubjectID()).thenReturn(new Subject().getValue());
        doThrow(new RuntimeException())
                .when(auditService)
                .submitAuditEvent(
                        any(),
                        anyString(),
                        anyString(),
                        anyString(),
                        anyString(),
                        anyString(),
                        anyString(),
                        anyString(),
                        anyString());

        // then
        assertDoesNotThrow(() -> underTest.removeAccount(Optional.of(input), userProfile));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Failed to audit account deletion")));
    }
}
