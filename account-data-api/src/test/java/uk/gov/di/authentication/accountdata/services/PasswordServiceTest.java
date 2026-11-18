package uk.gov.di.authentication.accountdata.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.accountdata.entity.password.failurereasons.VerifyPasswordFailureReason;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;

public class PasswordServiceTest {

    private final DynamoService dynamoService = mock(DynamoService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private PasswordService passwordService;

    @BeforeEach
    void setUp() {
        passwordService = new PasswordService(configurationService, dynamoService);
    }

    @Nested
    class VerifyPassword {

        @Test
        void shouldReturnTrueIfPasswordWasVerified() {
            when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                    .thenReturn(Optional.of(new UserProfile().withEmail(EMAIL)));
            when(dynamoService.login(anyString(), any())).thenReturn(true);

            var result = passwordService.verifyPassword(PUBLIC_SUBJECT_ID, "correctPassword");

            assertThat(result.isSuccess(), equalTo(true));
            assertThat(result.getSuccess(), equalTo(true));
        }

        @Test
        void shouldReturnFalseIfPasswordWasNotVerified() {
            when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                    .thenReturn(Optional.of(new UserProfile().withEmail(EMAIL)));
            when(dynamoService.login(anyString(), any())).thenReturn(false);

            var result = passwordService.verifyPassword(PUBLIC_SUBJECT_ID, "incorrectPassword");

            assertThat(result.isSuccess(), equalTo(true));
            assertThat(result.getSuccess(), equalTo(false));
        }

        @Test
        void shouldReturnUserProfileNotFoundWhenUserProfileNotFound() {
            when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                    .thenReturn(Optional.empty());

            var result = passwordService.verifyPassword(PUBLIC_SUBJECT_ID, "password123");

            assertThat(result.isFailure(), equalTo(true));
            assertThat(result.getFailure(), equalTo(VerifyPasswordFailureReason.USER_NOT_FOUND));
        }
    }
}
