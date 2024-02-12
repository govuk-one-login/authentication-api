package uk.gov.di.authentication.frontendapi.validation;

import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.TestClientHelper.isTestClientWithAllowedEmail;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public class EmailCodeProcessor extends MfaCodeProcessor {

    EmailCodeProcessor(
            CodeStorageService codeStorageService,
            UserContext userContext,
            ConfigurationService configurationService,
            AuthenticationService dynamoService,
            AuditService auditService,
            DynamoAccountModifiersService dynamoAccountModifiersService) {
        super(
                userContext,
                codeStorageService,
                configurationService.getCodeMaxRetries(),
                dynamoService,
                auditService,
                dynamoAccountModifiersService);
    }

    @Override
    public Optional<ErrorResponse> validateCode() {
        return Optional.empty();
    }

    @Override
    public void processSuccessfulCodeRequest(String ipAddress, String persistentSessionId) {
    }
}
