package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.passkeys.PasskeyRetrieveError;
import uk.gov.di.authentication.frontendapi.entity.passkeys.PasskeysRetrieveResponse;
import uk.gov.di.authentication.frontendapi.services.passkeys.PasskeysService;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PUBLIC_SUBJECT_ID;

class AccountDataCredentialRepositoryTest {

    private final PasskeysService passkeysService = mock(PasskeysService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AccountDataCredentialRepository repository =
            new AccountDataCredentialRepository(passkeysService, authenticationService);

    private static final String PASSKEY_ID_BASE64URL = "dGVzdC1jcmVkZW50aWFsLWlk";

    @Test
    void implementsCredentialRepository() {
        assertThat(repository, instanceOf(CredentialRepository.class));
    }

    @Nested
    class GetCredentialIdsForUsername {
        @Test
        void returnsCredentialIdsWhenPasskeysExist() {
            setupUserProfile();
            when(passkeysService.retrievePasskeys(PUBLIC_SUBJECT_ID))
                    .thenReturn(
                            Result.success(
                                    new PasskeysRetrieveResponse(
                                            List.of(aPasskeyResponse(PASSKEY_ID_BASE64URL)))));

            var result = repository.getCredentialIdsForUsername(EMAIL);

            assertThat(result, hasSize(1));
            var descriptor = result.iterator().next();
            assertThat(
                    descriptor.getId(),
                    equalTo(new ByteArray(Base64.getUrlDecoder().decode(PASSKEY_ID_BASE64URL))));
            assertThat(descriptor.getType(), equalTo(PublicKeyCredentialType.PUBLIC_KEY));
        }

        @Test
        void returnsEmptySetWhenNoPasskeys() {
            setupUserProfile();
            when(passkeysService.retrievePasskeys(PUBLIC_SUBJECT_ID))
                    .thenReturn(Result.success(new PasskeysRetrieveResponse(List.of())));

            var result = repository.getCredentialIdsForUsername(EMAIL);

            assertThat(result, hasSize(0));
        }

        @Test
        void returnsEmptySetWhenUserNotFound() {
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.empty());

            var result = repository.getCredentialIdsForUsername(EMAIL);

            assertThat(result, hasSize(0));
        }

        @Test
        void returnsEmptySetWhenApiCallFails() {
            setupUserProfile();
            when(passkeysService.retrievePasskeys(PUBLIC_SUBJECT_ID))
                    .thenReturn(
                            Result.failure(
                                    PasskeyRetrieveError.ERROR_RESPONSE_FROM_PASSKEY_RETRIEVE));

            var result = repository.getCredentialIdsForUsername(EMAIL);

            assertThat(result, hasSize(0));
        }
    }

    private void setupUserProfile() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(
                        Optional.of(
                                new UserProfile()
                                        .withEmail(EMAIL)
                                        .withPublicSubjectID(PUBLIC_SUBJECT_ID)));
    }

    private static PasskeysRetrieveResponse.PasskeyResponse aPasskeyResponse(String passkeyId) {
        return new PasskeysRetrieveResponse.PasskeyResponse(
                passkeyId,
                "cHVibGljLWtleS1jb3Nl",
                "some-aaguid",
                true,
                5,
                List.of(),
                true,
                true,
                "some-timestamp",
                "another-timestamp");
    }
}
