package uk.gov.di.authentication.frontendapi.validation;

import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.TestClientHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Optional;

public class MfaCodeProcessorFactory {

    private final ConfigurationService configurationService;
    private final CodeStorageService codeStorageService;
    private final AuthenticationService authenticationService;
    private final AuditService auditService;
    private final DynamoAccountModifiersService accountModifiersService;
    private final MFAMethodsService mfaMethodsService;
    private final TestClientHelper testClientHelper;

    public MfaCodeProcessorFactory(
            ConfigurationService configurationService,
            CodeStorageService codeStorageService,
            AuthenticationService authenticationService,
            AuditService auditService,
            DynamoAccountModifiersService accountModifiersService,
            MFAMethodsService mfaMethodsService,
            TestClientHelper testClientHelper) {
        this.configurationService = configurationService;
        this.codeStorageService = codeStorageService;
        this.authenticationService = authenticationService;
        this.auditService = auditService;
        this.accountModifiersService = accountModifiersService;
        this.mfaMethodsService = mfaMethodsService;
        this.testClientHelper = testClientHelper;
    }

    public Optional<MfaCodeProcessor> getMfaCodeProcessor(
            MFAMethodType mfaMethodType, CodeRequest codeRequest, UserContext userContext) {
        return switch (mfaMethodType) {
            case AUTH_APP -> {
                int codeMaxRetries =
                        List.of(JourneyType.REGISTRATION, JourneyType.ACCOUNT_RECOVERY)
                                        .contains(codeRequest.getJourneyType())
                                ? configurationService.getIncreasedCodeMaxRetries()
                                : configurationService.getCodeMaxRetries();
                yield Optional.of(
                        new AuthAppCodeProcessor(
                                userContext,
                                codeStorageService,
                                configurationService,
                                authenticationService,
                                codeMaxRetries,
                                codeRequest,
                                auditService,
                                accountModifiersService,
                                mfaMethodsService));
            }
            case SMS -> Optional.of(
                    new PhoneNumberCodeProcessor(
                            codeStorageService,
                            userContext,
                            configurationService,
                            codeRequest,
                            authenticationService,
                            auditService,
                            accountModifiersService,
                            mfaMethodsService,
                            testClientHelper));
            default -> Optional.empty();
        };
    }
}
