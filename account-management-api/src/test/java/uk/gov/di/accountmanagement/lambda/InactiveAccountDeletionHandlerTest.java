package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.services.AccountDeletionService;
import uk.gov.di.accountmanagement.services.InactiveAccountDeletionTokenService;
import uk.gov.di.authentication.auditevents.entity.AuthDeleteAccount;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.entity.JwtFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class InactiveAccountDeletionHandlerTest {

    private static final String PUBLIC_SUBJECT_ID = "urn:fdc:gov.uk:2022:abc123";
    private static final String LEGACY_SUBJECT_ID = "legacy-subject-id";
    private static final String EMAIL = "test@example.com";
    private static final String TOKEN_VALUE = "test-bearer-token";
    private static final String INTERNAL_SECTOR_URI = "https://identity.test.account.gov.uk";

    private final Context context = mock(Context.class);
    private final InactiveAccountDeletionTokenService tokenService =
            mock(InactiveAccountDeletionTokenService.class);
    private final AccountDeletionService accountDeletionService =
            mock(AccountDeletionService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final StructuredAuditService structuredAuditService =
            mock(StructuredAuditService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private InactiveAccountDeletionHandler handler;

    @BeforeEach
    void setUp() {
        handler =
                new InactiveAccountDeletionHandler(
                        tokenService,
                        accountDeletionService,
                        dynamoService,
                        structuredAuditService,
                        configurationService);
        when(tokenService.createAccountDataApiAccessToken(any()))
                .thenReturn(Result.success(new BearerAccessToken(TOKEN_VALUE)));
        when(dynamoService.getOptionalUserProfileFromPublicSubject(any()))
                .thenReturn(Optional.of(userProfileWithPublicSubjectId(PUBLIC_SUBJECT_ID)));
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(dynamoService.getOrGenerateSalt(any())).thenReturn(new byte[] {0x1});
    }

    @Test
    void shouldSuccessfullyDeleteAccountAndReportNoFailures() {
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");
        doNothing()
                .when(accountDeletionService)
                .deleteAccountViaDataApi(PUBLIC_SUBJECT_ID, TOKEN_VALUE);

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), is(empty()));
        verify(tokenService).createAccountDataApiAccessToken(PUBLIC_SUBJECT_ID);
        verify(accountDeletionService).deleteAccountViaDataApi(PUBLIC_SUBJECT_ID, TOKEN_VALUE);
    }

    @Test
    void shouldReportFailureWhenDeletionThrows() {
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");
        doThrow(new RuntimeException("Data API returned error status 500"))
                .when(accountDeletionService)
                .deleteAccountViaDataApi(any(), any());

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        assertEquals("msg-1", response.getBatchItemFailures().get(0).getItemIdentifier());
        verifyNoInteractions(structuredAuditService);
    }

    @Test
    void shouldReportFailureWhenTokenMintingFails() {
        when(tokenService.createAccountDataApiAccessToken(any()))
                .thenReturn(Result.failure(JwtFailureReason.SIGNING_ERROR));
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        assertEquals("msg-1", response.getBatchItemFailures().get(0).getItemIdentifier());
        verifyNoInteractions(accountDeletionService);
        verifyNoInteractions(structuredAuditService);
    }

    @Test
    void shouldReportMalformedJsonAsFailure() {
        var event = createSQSEventWithBody("not valid json");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        assertEquals("msg-1", response.getBatchItemFailures().get(0).getItemIdentifier());
        verifyNoInteractions(accountDeletionService);
    }

    @Test
    void shouldReportMissingPublicSubjectIdAsFailure() {
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"\"}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        verifyNoInteractions(accountDeletionService);
    }

    @Test
    void shouldReportNullPublicSubjectIdAsFailure() {
        var event = createSQSEventWithBody("{}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        verifyNoInteractions(accountDeletionService);
    }

    @Test
    void shouldHandleNullEvent() {
        SQSBatchResponse response = handler.handleRequest(null, context);

        assertThat(response.getBatchItemFailures(), is(empty()));
        verifyNoInteractions(accountDeletionService);
    }

    @Test
    void shouldReportFailureWhenUserProfileNotFound() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.empty());
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        assertEquals("msg-1", response.getBatchItemFailures().get(0).getItemIdentifier());
        verifyNoInteractions(accountDeletionService);
        verifyNoInteractions(structuredAuditService);
    }

    @Test
    void shouldProceedToDeletionWhenUserProfileFound() {
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), is(empty()));
        verify(dynamoService).getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID);
        verify(accountDeletionService).deleteAccountViaDataApi(PUBLIC_SUBJECT_ID, TOKEN_VALUE);
    }

    @Test
    void shouldEmitAuthDeleteAccountAuditEventOnSuccessfulDeletion() {
        var userProfile = userProfileWithPublicSubjectId(PUBLIC_SUBJECT_ID);
        userProfile.setLegacySubjectID(LEGACY_SUBJECT_ID);
        userProfile.setEmail(EMAIL);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.of(userProfile));
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), is(empty()));
        var captor = ArgumentCaptor.forClass(AuthDeleteAccount.class);
        verify(structuredAuditService).submitAuditEvent(captor.capture());
        var auditEvent = captor.getValue();

        assertEquals("AUTH_DELETE_ACCOUNT", auditEvent.eventName());
        assertEquals(PUBLIC_SUBJECT_ID, auditEvent.user().publicSubjectId());
        assertEquals(LEGACY_SUBJECT_ID, auditEvent.user().legacySubjectId());
        assertEquals(
                AccountDeletionReason.INACTIVE_ACCOUNT.name(),
                auditEvent.extensions().accountDeletionReason());
    }

    @Test
    void shouldNotEmitAuditEventWhenDeletionFails() {
        doThrow(new RuntimeException("Data API returned error status 500"))
                .when(accountDeletionService)
                .deleteAccountViaDataApi(any(), any());
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

        handler.handleRequest(event, context);

        verifyNoInteractions(structuredAuditService);
    }

    @Test
    void shouldNotReportFailureWhenAuditEmissionFails() {
        doThrow(new RuntimeException("Failed to send to SQS"))
                .when(structuredAuditService)
                .submitAuditEvent(any());
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), is(empty()));
        verify(accountDeletionService).deleteAccountViaDataApi(PUBLIC_SUBJECT_ID, TOKEN_VALUE);
    }

    @Test
    void shouldProcessBatchWithMixedSuccessAndFailure() {
        var goodMessage = createSQSMessage("msg-good", "{\"publicSubjectId\": \"sub-1\"}");
        var badMessage = createSQSMessage("msg-bad", "invalid json");
        var failingMessage = createSQSMessage("msg-fail", "{\"publicSubjectId\": \"sub-2\"}");

        when(dynamoService.getOptionalUserProfileFromPublicSubject("sub-1"))
                .thenReturn(Optional.of(userProfileWithPublicSubjectId("sub-1")));
        when(dynamoService.getOptionalUserProfileFromPublicSubject("sub-2"))
                .thenReturn(Optional.of(userProfileWithPublicSubjectId("sub-2")));
        doNothing().when(accountDeletionService).deleteAccountViaDataApi(eq("sub-1"), any());
        doThrow(new RuntimeException("5xx"))
                .when(accountDeletionService)
                .deleteAccountViaDataApi(eq("sub-2"), any());

        var event = new SQSEvent();
        event.setRecords(List.of(goodMessage, badMessage, failingMessage));

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(2));
        assertEquals("msg-bad", response.getBatchItemFailures().get(0).getItemIdentifier());
        assertEquals("msg-fail", response.getBatchItemFailures().get(1).getItemIdentifier());
        verify(structuredAuditService, times(1)).submitAuditEvent(any());
    }

    private UserProfile userProfileWithPublicSubjectId(String publicSubjectId) {
        var userProfile = new UserProfile();
        userProfile.setPublicSubjectID(publicSubjectId);
        userProfile.setSubjectID(publicSubjectId);
        return userProfile;
    }

    private SQSEvent createSQSEventWithBody(String body) {
        var message = createSQSMessage("msg-1", body);
        var event = new SQSEvent();
        event.setRecords(List.of(message));
        return event;
    }

    private SQSMessage createSQSMessage(String messageId, String body) {
        var message = new SQSMessage();
        message.setMessageId(messageId);
        message.setBody(body);
        return message;
    }
}
