package uk.gov.di.accountmanagement.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
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
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
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
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class ManualAccountDeletionServiceTest {
    private final AccountDeletionService accountDeletionService =
            mock(AccountDeletionService.class);
    private final AwsSnsClient legacyAccountDeletionSnsClient = mock(AwsSnsClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ManualAccountDeletionService underTest =
            new ManualAccountDeletionService(
                    accountDeletionService, legacyAccountDeletionSnsClient, configurationService);
    private static final UserProfile USER_PROFILE = mock(UserProfile.class);
    private static final String PUBLIC_SUBJECT_ID = "publicSubject";
    private static final String LEGACY_SUBJECT_ID = "legacySubject";
    private static final String SUBJECT_ID = "subjectId";
    private static final String COMMON_SUBJECT_ID =
            "urn:fdc:gov.uk:2022:xH7hrtJCgdi2NEF7TXcOC6SMz8DohdoLo9hWqQMWPRk";
    private static final ByteBuffer SALT =
            ByteBuffer.wrap(
                    "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw="
                            .getBytes(StandardCharsets.UTF_8));

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ManualAccountDeletionService.class);

    @BeforeEach
    void setUp() {
        when(USER_PROFILE.getPublicSubjectID()).thenReturn(PUBLIC_SUBJECT_ID);
        when(USER_PROFILE.getLegacySubjectID()).thenReturn(LEGACY_SUBJECT_ID);
        when(USER_PROFILE.getSubjectID()).thenReturn(SUBJECT_ID);
        when(USER_PROFILE.getSalt()).thenReturn(SALT);
        when(configurationService.getInternalSectorUri())
                .thenReturn("https://identity.test.account.gov.uk");
    }

    @Test
    void shouldCallRemoveAccountWithCorrectParameters() throws Json.JsonException {
        // when
        underTest.manuallyDeleteAccount(USER_PROFILE);

        // then
        verify(accountDeletionService)
                .removeAccount(
                        Optional.empty(),
                        USER_PROFILE,
                        AuditService.UNKNOWN,
                        AccountDeletionReason.SUPPORT_INITIATED,
                        true,
                        Optional.empty());
    }

    @Test
    void shouldSubmitMessageToLegacyAccountDeletionQueue() {
        // given
        var expectedSqsPayload =
                String.format(
                        "{\"public_subject_id\":\"%s\",\"legacy_subject_id\":\"%s\",\"user_id\":\"%s\"}",
                        PUBLIC_SUBJECT_ID, LEGACY_SUBJECT_ID, COMMON_SUBJECT_ID);

        // when
        underTest.manuallyDeleteAccount(USER_PROFILE);

        // then
        verify(legacyAccountDeletionSnsClient).publish(expectedSqsPayload);
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
        doThrow(new RuntimeException("error"))
                .when(accountDeletionService)
                .removeAccount(any(), any(), any(), any(), anyBoolean(), any());

        // then
        assertThrows(RuntimeException.class, () -> underTest.manuallyDeleteAccount(USER_PROFILE));
        assertThat(
                logging.events(), hasItem(withMessageContaining("Error while deleting account")));
    }

    @Nested
    class WithTokenMinting {
        private final AccountDeletionTokenService accountDeletionTokenService =
                mock(AccountDeletionTokenService.class);
        private static final String CLIENT_ID = "manual-account-deletion";
        private static final String TOKEN_VALUE = "test-bearer-token";
        private final ManualAccountDeletionService underTestWithMinter =
                new ManualAccountDeletionService(
                        accountDeletionService,
                        legacyAccountDeletionSnsClient,
                        configurationService,
                        accountDeletionTokenService,
                        CLIENT_ID);

        @Test
        void shouldMintTokenAndPassItToRemoveAccount() throws Json.JsonException {
            // given
            when(configurationService.isAccountDeletionDataApiEnabled()).thenReturn(true);
            when(accountDeletionTokenService.createAccountDataApiAccessToken(
                            PUBLIC_SUBJECT_ID, CLIENT_ID))
                    .thenReturn(Result.success(new BearerAccessToken(TOKEN_VALUE)));

            // when
            underTestWithMinter.manuallyDeleteAccount(USER_PROFILE);

            // then
            verify(accountDeletionService)
                    .removeAccount(
                            Optional.empty(),
                            USER_PROFILE,
                            AuditService.UNKNOWN,
                            AccountDeletionReason.SUPPORT_INITIATED,
                            true,
                            Optional.of(TOKEN_VALUE));
        }

        @Test
        void shouldFallBackToDynamoWhenFeatureFlagIsOff() throws Json.JsonException {
            // given
            when(configurationService.isAccountDeletionDataApiEnabled()).thenReturn(false);

            // when
            underTestWithMinter.manuallyDeleteAccount(USER_PROFILE);

            // then
            verify(accountDeletionService)
                    .removeAccount(
                            Optional.empty(),
                            USER_PROFILE,
                            AuditService.UNKNOWN,
                            AccountDeletionReason.SUPPORT_INITIATED,
                            true,
                            Optional.empty());
            verifyNoInteractions(accountDeletionTokenService);
        }

        @Test
        void shouldThrowIfTokenMintingFails() {
            // given
            when(configurationService.isAccountDeletionDataApiEnabled()).thenReturn(true);
            when(accountDeletionTokenService.createAccountDataApiAccessToken(
                            PUBLIC_SUBJECT_ID, CLIENT_ID))
                    .thenReturn(Result.failure(JwtFailureReason.SIGNING_ERROR));

            // then
            assertThrows(
                    RuntimeException.class,
                    () -> underTestWithMinter.manuallyDeleteAccount(USER_PROFILE));
            verify(accountDeletionService, never())
                    .removeAccount(any(), any(), any(), any(), anyBoolean(), any());
            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Error while deleting account")));
        }
    }
}
