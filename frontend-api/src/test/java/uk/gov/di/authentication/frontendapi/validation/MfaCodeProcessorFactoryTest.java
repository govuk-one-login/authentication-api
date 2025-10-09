package uk.gov.di.authentication.frontendapi.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.TestUserHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MfaCodeProcessorFactoryTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final AuthSessionItem authSession = mock(AuthSessionItem.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private final DynamoAccountModifiersService accountModifiersService =
            mock(DynamoAccountModifiersService.class);
    private final TestUserHelper testUserHelper = mock(TestUserHelper.class);
    private final MfaCodeProcessorFactory mfaCodeProcessorFactory =
            new MfaCodeProcessorFactory(
                    configurationService,
                    codeStorageService,
                    authenticationService,
                    auditService,
                    accountModifiersService,
                    mfaMethodsService,
                    testUserHelper);

    @BeforeEach
    void setUp() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getIncreasedCodeMaxRetries()).thenReturn(999999);

        when(authSession.getEmailAddress()).thenReturn("test@test.com");
        when(userContext.getAuthSession()).thenReturn(authSession);
    }

    @Test
    void whenMfaMethodGeneratesAuthAppCodeProcessor() {
        var mfaCodeProcessor =
                mfaCodeProcessorFactory.getMfaCodeProcessor(
                        MFAMethodType.AUTH_APP,
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP, "111111", JourneyType.REGISTRATION),
                        userContext);

        assertInstanceOf(AuthAppCodeProcessor.class, mfaCodeProcessor.get());
    }

    @Test
    void whenMfaMethodGeneratesPhoneNumberCodeProcessor() {
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        var mfaCodeProcessor =
                mfaCodeProcessorFactory.getMfaCodeProcessor(
                        MFAMethodType.SMS,
                        new VerifyMfaCodeRequest(
                                MFAMethodType.SMS, "111111", JourneyType.REGISTRATION),
                        userContext);

        assertInstanceOf(PhoneNumberCodeProcessor.class, mfaCodeProcessor.get());
    }
}
