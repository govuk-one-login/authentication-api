package uk.gov.di.authentication.shared.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MfaCodeValidatorFactoryTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final Session session = mock(Session.class);
    private final MfaCodeValidatorFactory mfaCodeValidatorFactory =
            new MfaCodeValidatorFactory(
                    configurationService, codeStorageService, authenticationService);

    @BeforeEach
    void setUp() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getCodeMaxRetriesRegistration()).thenReturn(999999);
        when(session.getEmailAddress()).thenReturn("test@test.com");

        when(userContext.getSession()).thenReturn(session);
    }

    @Test
    void whenMfaMethodGeneratesAuthAppCodeValidator() {
        var mfaCodeValidator =
                mfaCodeValidatorFactory.getMfaCodeValidator(
                        MFAMethodType.AUTH_APP, true, userContext);

        assertInstanceOf(AuthAppCodeValidator.class, mfaCodeValidator.get());
    }
}
