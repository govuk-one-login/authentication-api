package uk.gov.di.authentication.frontendapi.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class EmailCodeProcessorTest {
    private EmailCodeProcessor processor;

    private final AuditService auditService = mock(AuditService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoAccountModifiersService accountModifiersService =
            mock(DynamoAccountModifiersService.class);

    @BeforeEach
    void setup() {
        processor = new EmailCodeProcessor(codeStorageService, userContext, configurationService, authenticationService, auditService, accountModifiersService);
    }

    @Test
    void shouldReturnNullWhenCorrectEmailCodeProcessed() {
        processor.validateCode();
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        any(),
                        any(),
                        any(),
                        any(),
                        any(),
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        any(),
                        pair("notification-type", VERIFY_EMAIL.name())
                );
    }

}
