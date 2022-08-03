package uk.gov.di.authentication.shared.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.validation.MfaCodeValidatorFactory.getMfaCodeValidator;

class MfaCodeValidatorFactoryTest {
    private ConfigurationService configurationService;
    private UserContext userContext;
    private CodeStorageService codeStorageService;
    private DynamoService dynamoService;
    private Session session;
    private final int CODE_MAX_RETRIES = 5;
    private final int CODE_MAX_RETRIES_REGISTRATION = 999999;
    private final String EMAIL_ADDRESS = "test@test.com";

    @BeforeEach
    void setUp() {
        this.configurationService = mock(ConfigurationService.class);
        when(configurationService.getCodeMaxRetries()).thenReturn(CODE_MAX_RETRIES);
        when(configurationService.getCodeMaxRetriesRegistration())
                .thenReturn(CODE_MAX_RETRIES_REGISTRATION);

        this.session = mock(Session.class);
        when(session.getEmailAddress()).thenReturn(EMAIL_ADDRESS);

        this.userContext = mock(UserContext.class);
        when(userContext.getSession()).thenReturn(session);

        this.codeStorageService = mock(CodeStorageService.class);
        this.dynamoService = mock(DynamoService.class);
    }

    @Test
    void whenMfaMethodGeneratesAuthAppCodeValidator() {
        var mfaCodeValidator =
                getMfaCodeValidator(
                        MFAMethodType.AUTH_APP,
                        true,
                        userContext,
                        codeStorageService,
                        configurationService,
                        dynamoService);

        assertInstanceOf(AuthAppCodeValidator.class, mfaCodeValidator.get());
    }
}
