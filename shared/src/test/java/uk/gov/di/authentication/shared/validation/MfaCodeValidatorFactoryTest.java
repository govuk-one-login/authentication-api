package uk.gov.di.authentication.shared.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MfaCodeValidatorFactoryTest {
    private ConfigurationService configurationService;
    private UserContext userContext;
    private CodeStorageService codeStorageService;
    private DynamoService dynamoService;
    private final int CODE_MAX_RETRIES = 5;
    private final int CODE_MAX_RETRIES_REGISTRATION = 999999;

    @BeforeEach
    void setUp() {
        this.configurationService = mock(ConfigurationService.class);
        when(configurationService.getCodeMaxRetries()).thenReturn(CODE_MAX_RETRIES);
        when(configurationService.getCodeMaxRetriesRegistration())
                .thenReturn(CODE_MAX_RETRIES_REGISTRATION);
        this.userContext = mock(UserContext.class);
        this.codeStorageService = mock(CodeStorageService.class);
        this.dynamoService = mock(DynamoService.class);
    }

    @Test
    void whenMfaMethodGeneratesAuthAppCodeValidator() {
        var mfaCodeValidator =
                uk.gov.di.authentication.shared.validation.MfaCodeValidatorFactory
                        .getMfaCodeValidator(
                                MFAMethodType.AUTH_APP,
                                true,
                                userContext,
                                codeStorageService,
                                configurationService,
                                dynamoService);

        assertInstanceOf(AuthAppCodeValidator.class, mfaCodeValidator.get());
    }
}
