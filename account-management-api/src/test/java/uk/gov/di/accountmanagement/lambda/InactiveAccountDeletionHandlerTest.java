package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.services.AccountDeletionService;
import uk.gov.di.accountmanagement.services.InactiveAccountDeletionTokenService;
import uk.gov.di.authentication.shared.entity.JwtFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class InactiveAccountDeletionHandlerTest {

    private static final String PUBLIC_SUBJECT_ID = "urn:fdc:gov.uk:2022:abc123";
    private static final String TOKEN_VALUE = "test-bearer-token";

    private final Context context = mock(Context.class);
    private final InactiveAccountDeletionTokenService tokenService =
            mock(InactiveAccountDeletionTokenService.class);
    private final AccountDeletionService accountDeletionService =
            mock(AccountDeletionService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private InactiveAccountDeletionHandler handler;

    @BeforeEach
    void setUp() {
        handler =
                new InactiveAccountDeletionHandler(
                        tokenService, accountDeletionService, dynamoService);
        when(tokenService.createAccountDataApiAccessToken(any()))
                .thenReturn(Result.success(new BearerAccessToken(TOKEN_VALUE)));
        when(dynamoService.getOptionalUserProfileFromPublicSubject(any()))
                .thenReturn(Optional.of(userProfileWithPublicSubjectId(PUBLIC_SUBJECT_ID)));
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
    }

    private UserProfile userProfileWithPublicSubjectId(String publicSubjectId) {
        var userProfile = new UserProfile();
        userProfile.setPublicSubjectID(publicSubjectId);
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
