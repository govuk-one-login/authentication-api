package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.services.AccountDeletionService;
import uk.gov.di.accountmanagement.services.InactiveAccountDeletionTokenService;
import uk.gov.di.authentication.auditevents.entity.AuthDeleteAccount;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.entity.JwtFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.GUARDRAIL_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.GUARDRAIL_PREVENTED_INACTIVE_ACCOUNT_DELETION;

class InactiveAccountDeletionHandlerTest {

    private static final String PUBLIC_SUBJECT_ID = "urn:fdc:gov.uk:2022:abc123";
    private static final String LEGACY_SUBJECT_ID = "legacy-subject-id";
    private static final String EMAIL = "test@example.com";
    private static final String TOKEN_VALUE = "test-bearer-token";
    private static final String INTERNAL_SECTOR_URI = "https://identity.test.account.gov.uk";
    private static final String TEST_ENVIRONMENT = "test";

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-09-04T14:00:00Z"), ZoneOffset.UTC);

    private static final String OLD_TIMESTAMP = "2019-01-01T10:00:00.000000";
    private static final String RECENT_TIMESTAMP = "2025-06-15T10:00:00.000000";

    private final Context context = mock(Context.class);
    private final InactiveAccountDeletionTokenService tokenService =
            mock(InactiveAccountDeletionTokenService.class);
    private final AccountDeletionService accountDeletionService =
            mock(AccountDeletionService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final StructuredAuditService structuredAuditService =
            mock(StructuredAuditService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private InactiveAccountDeletionHandler handler;

    @BeforeEach
    void setUp() {
        handler =
                new InactiveAccountDeletionHandler(
                        tokenService,
                        accountDeletionService,
                        dynamoService,
                        structuredAuditService,
                        configurationService,
                        cloudwatchMetricsService,
                        FIXED_CLOCK);
        when(tokenService.createAccountDataApiAccessToken(any()))
                .thenReturn(Result.success(new BearerAccessToken(TOKEN_VALUE)));
        when(dynamoService.getOptionalUserProfileFromPublicSubject(any()))
                .thenReturn(Optional.of(inactiveUserProfile(PUBLIC_SUBJECT_ID, EMAIL)));
        when(dynamoService.getUserCredentialsFromEmail(any()))
                .thenReturn(inactiveUserCredentials());
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.getEnvironment()).thenReturn(TEST_ENVIRONMENT);
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
    void shouldProceedToDeletionWhenUserProfileFound() {
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), is(empty()));
        verify(dynamoService).getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID);
        verify(accountDeletionService).deleteAccountViaDataApi(PUBLIC_SUBJECT_ID, TOKEN_VALUE);
    }

    @Test
    void shouldEmitAuthDeleteAccountAuditEventOnSuccessfulDeletion() {
        var userProfile = inactiveUserProfile(PUBLIC_SUBJECT_ID, EMAIL);
        userProfile.setLegacySubjectID(LEGACY_SUBJECT_ID);
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
                .thenReturn(Optional.of(inactiveUserProfile("sub-1", "sub1@example.com")));
        when(dynamoService.getOptionalUserProfileFromPublicSubject("sub-2"))
                .thenReturn(Optional.of(inactiveUserProfile("sub-2", "sub2@example.com")));
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

    @Nested
    class UserProfileNotFoundTest {

        @Test
        void shouldSkipWithNoFailureWhenUserProfileNotFound() {
            when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                    .thenReturn(Optional.empty());
            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            SQSBatchResponse response = handler.handleRequest(event, context);

            assertThat(response.getBatchItemFailures(), is(empty()));
            verifyNoInteractions(accountDeletionService);
            verifyNoInteractions(structuredAuditService);
        }
    }

    @Nested
    class InactivityFailsafeCheckTest {

        @Test
        void shouldReportFailureWhenAccountHasRecentActivity() {
            var recentProfile = new UserProfile();
            recentProfile.setPublicSubjectID(PUBLIC_SUBJECT_ID);
            recentProfile.setSubjectID(PUBLIC_SUBJECT_ID);
            recentProfile.setEmail(EMAIL);
            recentProfile.setCreated(OLD_TIMESTAMP);
            recentProfile.setUpdated(RECENT_TIMESTAMP);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                    .thenReturn(Optional.of(recentProfile));

            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            SQSBatchResponse response = handler.handleRequest(event, context);

            assertThat(response.getBatchItemFailures(), hasSize(1));
            assertEquals("msg-1", response.getBatchItemFailures().get(0).getItemIdentifier());
            verifyNoInteractions(accountDeletionService);
            verifyNoInteractions(structuredAuditService);
        }

        @Test
        void shouldProceedWithDeletionWhenAllTimestampsOld() {
            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            SQSBatchResponse response = handler.handleRequest(event, context);

            assertThat(response.getBatchItemFailures(), is(empty()));
            verify(accountDeletionService).deleteAccountViaDataApi(PUBLIC_SUBJECT_ID, TOKEN_VALUE);
            verify(structuredAuditService).submitAuditEvent(any());
        }

        @Test
        void shouldProceedWithDeletionWhenUserCredentialsNotFound() {
            when(dynamoService.getUserCredentialsFromEmail(any())).thenReturn(null);
            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            SQSBatchResponse response = handler.handleRequest(event, context);

            assertThat(response.getBatchItemFailures(), is(empty()));
            verify(accountDeletionService).deleteAccountViaDataApi(PUBLIC_SUBJECT_ID, TOKEN_VALUE);
        }

        @Test
        void shouldReportFailureWhenCredentialsHaveRecentActivity() {
            var recentCredentials = new UserCredentials();
            recentCredentials.setCreated(OLD_TIMESTAMP);
            recentCredentials.setUpdated(RECENT_TIMESTAMP);
            when(dynamoService.getUserCredentialsFromEmail(any())).thenReturn(recentCredentials);

            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            SQSBatchResponse response = handler.handleRequest(event, context);

            assertThat(response.getBatchItemFailures(), hasSize(1));
            assertEquals("msg-1", response.getBatchItemFailures().get(0).getItemIdentifier());
            verifyNoInteractions(accountDeletionService);
            verifyNoInteractions(structuredAuditService);
        }

        @Test
        void shouldReportFailureWhenTermsAndConditionsTimestampIsRecent() {
            var userProfile = inactiveUserProfile(PUBLIC_SUBJECT_ID, EMAIL);
            userProfile.setTermsAndConditions(new TermsAndConditions("1.0", RECENT_TIMESTAMP));
            when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                    .thenReturn(Optional.of(userProfile));

            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            SQSBatchResponse response = handler.handleRequest(event, context);

            assertThat(response.getBatchItemFailures(), hasSize(1));
            verifyNoInteractions(accountDeletionService);
        }

        @Test
        void shouldReportFailureWhenLastSignedInIsRecent() {
            var userProfile = inactiveUserProfile(PUBLIC_SUBJECT_ID, EMAIL);
            userProfile.setLastSignedIn(RECENT_TIMESTAMP);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                    .thenReturn(Optional.of(userProfile));

            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            SQSBatchResponse response = handler.handleRequest(event, context);

            assertThat(response.getBatchItemFailures(), hasSize(1));
            verifyNoInteractions(accountDeletionService);
        }

        @Test
        void shouldLookUpCredentialsByEmailFromUserProfile() {
            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            handler.handleRequest(event, context);

            verify(dynamoService).getUserCredentialsFromEmail(EMAIL);
        }

        @Test
        void shouldHandleBatchWithMixOfActiveAndInactiveAccounts() {
            var inactiveMessage =
                    createSQSMessage("msg-inactive", "{\"publicSubjectId\": \"inactive-sub\"}");
            var activeMessage =
                    createSQSMessage("msg-active", "{\"publicSubjectId\": \"active-sub\"}");

            var inactiveProfile = inactiveUserProfile("inactive-sub", "inactive@example.com");
            var activeProfile = new UserProfile();
            activeProfile.setPublicSubjectID("active-sub");
            activeProfile.setSubjectID("active-sub");
            activeProfile.setEmail("active@example.com");
            activeProfile.setCreated(RECENT_TIMESTAMP);
            activeProfile.setUpdated(RECENT_TIMESTAMP);

            when(dynamoService.getOptionalUserProfileFromPublicSubject("inactive-sub"))
                    .thenReturn(Optional.of(inactiveProfile));
            when(dynamoService.getOptionalUserProfileFromPublicSubject("active-sub"))
                    .thenReturn(Optional.of(activeProfile));
            doNothing()
                    .when(accountDeletionService)
                    .deleteAccountViaDataApi(eq("inactive-sub"), any());

            var event = new SQSEvent();
            event.setRecords(List.of(inactiveMessage, activeMessage));

            SQSBatchResponse response = handler.handleRequest(event, context);

            assertThat(response.getBatchItemFailures(), hasSize(1));
            assertEquals("msg-active", response.getBatchItemFailures().get(0).getItemIdentifier());
            verify(accountDeletionService).deleteAccountViaDataApi(eq("inactive-sub"), any());
            verify(accountDeletionService, never())
                    .deleteAccountViaDataApi(eq("active-sub"), any());
        }

        @Test
        void shouldEmitGuardrailMetricWhenAccountHasRecentActivity() {
            var recentProfile = inactiveUserProfile(PUBLIC_SUBJECT_ID, EMAIL);
            recentProfile.setUpdated(RECENT_TIMESTAMP);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                    .thenReturn(Optional.of(recentProfile));

            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            handler.handleRequest(event, context);

            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            GUARDRAIL_PREVENTED_INACTIVE_ACCOUNT_DELETION.getValue(),
                            Map.of(
                                    GUARDRAIL_TYPE.getValue(),
                                    "AuthUserActivityCheck",
                                    ENVIRONMENT.getValue(),
                                    TEST_ENVIRONMENT),
                            CloudwatchMetricsService.HOME_READ_ONLY_NAMESPACE);
        }

        @Test
        void shouldNotEmitGuardrailMetricWhenAccountIsInactive() {
            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            handler.handleRequest(event, context);

            verifyNoInteractions(cloudwatchMetricsService);
        }

        @Test
        void shouldNotEmitGuardrailMetricWhenUserProfileNotFound() {
            when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                    .thenReturn(Optional.empty());
            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            handler.handleRequest(event, context);

            verifyNoInteractions(cloudwatchMetricsService);
        }

        @Test
        void shouldStillThrowRecentlyActiveAccountExceptionWhenMetricEmissionFails() {
            var recentProfile = inactiveUserProfile(PUBLIC_SUBJECT_ID, EMAIL);
            recentProfile.setUpdated(RECENT_TIMESTAMP);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                    .thenReturn(Optional.of(recentProfile));
            doThrow(new RuntimeException("CloudWatch error"))
                    .when(cloudwatchMetricsService)
                    .incrementCounter(any(), any(Map.class), any());

            var event =
                    createSQSEventWithBody("{\"publicSubjectId\": \"" + PUBLIC_SUBJECT_ID + "\"}");

            SQSBatchResponse response = handler.handleRequest(event, context);

            assertThat(response.getBatchItemFailures(), hasSize(1));
            verifyNoInteractions(accountDeletionService);
        }
    }

    private UserProfile inactiveUserProfile(String publicSubjectId, String email) {
        var userProfile = new UserProfile();
        userProfile.setPublicSubjectID(publicSubjectId);
        userProfile.setSubjectID(publicSubjectId);
        userProfile.setEmail(email);
        userProfile.setCreated(OLD_TIMESTAMP);
        userProfile.setUpdated(OLD_TIMESTAMP);
        return userProfile;
    }

    private UserCredentials inactiveUserCredentials() {
        var userCredentials = new UserCredentials();
        userCredentials.setCreated(OLD_TIMESTAMP);
        userCredentials.setUpdated(OLD_TIMESTAMP);
        return userCredentials;
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
