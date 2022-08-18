package uk.gov.di.authentication.sharedtest.helper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.validation.AuthAppCodeValidator;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class AuthAppStubTest {
    AuthAppStub authAppStub;
    AuthAppCodeValidator authAppCodeValidator;

    @BeforeEach
    void setUp() {
        this.authAppStub = new AuthAppStub();
        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        mock(String.class),
                        mock(CodeStorageService.class),
                        mock(ConfigurationService.class),
                        mock(DynamoService.class),
                        99999);
    }

    @Test
    void worksWithAuthAppCodeValidatorAlgorithm() {
        String generatedCode = authAppStub.getAuthAppOneTimeCode("ORSXG5BNORSXQ5A=");

        assertTrue(authAppCodeValidator.isCodeValid(generatedCode, "ORSXG5BNORSXQ5A="));
    }
}
