package uk.gov.di.authentication.sharedtest.helper;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.frontendapi.validation.AuthAppCodeProcessor;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthAppStubTest {
    private AuthAppStub authAppStub;
    private AuthAppCodeProcessor authAppCodeProcessor;
    private static ConfigurationService configurationService;
    private final UserContext userContext = mock(UserContext.class);

    @BeforeAll
    static void init() {
        configurationService = mock(ConfigurationService.class);
        when(configurationService.getAuthAppCodeWindowLength()).thenReturn(30);
    }

    @BeforeEach
    void setUp() {
        this.authAppStub = new AuthAppStub();
        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        userContext,
                        mock(CodeStorageService.class),
                        configurationService,
                        mock(DynamoService.class),
                        99999,
                        mock(CodeRequest.class),
                        mock(AuditService.class),
                        mock(DynamoAccountModifiersService.class),
                        mock(MFAMethodsService.class));
    }

    @Test
    void worksWithAuthAppCodeProcessorAlgorithm() {
        String generatedCode =
                authAppStub.getAuthAppOneTimeCode(
                        "ABCDAAWOXKUQCDH5QMSPHAGJXMTXFZRZAKFTR6Y3Q5YRN5EVOYRQ");

        assertTrue(
                authAppCodeProcessor.isCodeValid(
                        generatedCode, "ABCDAAWOXKUQCDH5QMSPHAGJXMTXFZRZAKFTR6Y3Q5YRN5EVOYRQ"));
    }
}
