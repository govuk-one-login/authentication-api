package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.CredentialRepository;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.services.passkeys.PasskeysService;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.mockito.Mockito.mock;

class AccountDataCredentialRepositoryTest {

    private final PasskeysService passkeysService = mock(PasskeysService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AccountDataCredentialRepository repository =
            new AccountDataCredentialRepository(passkeysService, authenticationService);

    @Test
    void implementsCredentialRepository() {
        assertThat(repository, instanceOf(CredentialRepository.class));
    }
}
