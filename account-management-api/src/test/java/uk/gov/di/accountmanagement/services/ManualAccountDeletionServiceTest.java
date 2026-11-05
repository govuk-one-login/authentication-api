package uk.gov.di.accountmanagement.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.entity.DeletedAccountIdentifiers;
import uk.gov.di.authentication.shared.entity.JwtFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class ManualAccountDeletionServiceTest {
    private final AccountDeletionService accountDeletionService =
            mock(AccountDeletionService.class);
    private final AccountDeletionTokenService accountDeletionTokenService =
            mock(AccountDeletionTokenService.class);
    private static final String CLIENT_ID = "manual-account-deletion";
    private static final String TOKEN_VALUE = "test-bearer-token";
    private final ManualAccountDeletionService underTest =
            new ManualAccountDeletionService(
                    accountDeletionService, accountDeletionTokenService, CLIENT_ID);
    private static final UserProfile USER_PROFILE = mock(UserProfile.class);
    private static final String PUBLIC_SUBJECT_ID = "publicSubject";
    private static final String LEGACY_SUBJECT_ID = "legacySubject";
    private static final String SUBJECT_ID = "subjectId";

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ManualAccountDeletionService.class);

    @BeforeEach
    void setUp() {
        when(USER_PROFILE.getPublicSubjectID()).thenReturn(PUBLIC_SUBJECT_ID);
        when(USER_PROFILE.getLegacySubjectID()).thenReturn(LEGACY_SUBJECT_ID);
        when(USER_PROFILE.getSubjectID()).thenReturn(SUBJECT_ID);
    }

    @Test
    void shouldMintTokenAndPassItToRemoveAccount() {
        // given
        when(accountDeletionTokenService.createAccountDataApiAccessToken(
                        PUBLIC_SUBJECT_ID, CLIENT_ID))
                .thenReturn(Result.success(new BearerAccessToken(TOKEN_VALUE)));

        // when
        underTest.manuallyDeleteAccount(USER_PROFILE);

        // then
        verify(accountDeletionService)
                .removeAccount(
                        USER_PROFILE,
                        AuditService.UNKNOWN,
                        AccountDeletionReason.SUPPORT_INITIATED,
                        true,
                        TOKEN_VALUE);
    }

    @ParameterizedTest
    @MethodSource("identifiersSource")
    void shouldReturnCorrectAccountIdentifiers(
            String expectedPublicSubjectId,
            String expectedLegacySubjectId,
            String expectedSubjectId) {
        // given
        when(USER_PROFILE.getPublicSubjectID()).thenReturn(expectedPublicSubjectId);
        when(USER_PROFILE.getLegacySubjectID()).thenReturn(expectedLegacySubjectId);
        when(USER_PROFILE.getSubjectID()).thenReturn(expectedSubjectId);
        when(accountDeletionTokenService.createAccountDataApiAccessToken(any(), any()))
                .thenReturn(Result.success(new BearerAccessToken(TOKEN_VALUE)));
        var expectedDeletedAccountIdentifiers =
                new DeletedAccountIdentifiers(
                        expectedPublicSubjectId, expectedLegacySubjectId, expectedSubjectId);

        // when
        var result = underTest.manuallyDeleteAccount(USER_PROFILE);

        // then
        assertEquals(expectedDeletedAccountIdentifiers, result);
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
    void shouldThrowExceptionIfAccountDeletionFails() {
        // given
        when(accountDeletionTokenService.createAccountDataApiAccessToken(
                        PUBLIC_SUBJECT_ID, CLIENT_ID))
                .thenReturn(Result.success(new BearerAccessToken(TOKEN_VALUE)));
        doThrow(new RuntimeException("error"))
                .when(accountDeletionService)
                .removeAccount(any(), any(), any(), anyBoolean(), any());

        // then
        assertThrows(RuntimeException.class, () -> underTest.manuallyDeleteAccount(USER_PROFILE));
        assertThat(
                logging.events(), hasItem(withMessageContaining("Error while deleting account")));
    }

    @Test
    void shouldThrowIfTokenMintingFails() {
        // given
        when(accountDeletionTokenService.createAccountDataApiAccessToken(
                        PUBLIC_SUBJECT_ID, CLIENT_ID))
                .thenReturn(Result.failure(JwtFailureReason.SIGNING_ERROR));

        // then
        assertThrows(RuntimeException.class, () -> underTest.manuallyDeleteAccount(USER_PROFILE));
        verify(accountDeletionService, never())
                .removeAccount(any(), any(), any(), any(), anyBoolean(), any());
        assertThat(
                logging.events(), hasItem(withMessageContaining("Error while deleting account")));
    }
}
