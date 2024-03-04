package uk.gov.di.authentication.frontendapi.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class EmailCodeProcessorTest {
    private final AuditService auditService = mock(AuditService.class);

    private EmailCodeProcessor processor;

    @BeforeEach
    void setup() {
        processor = new EmailCodeProcessor(null, null, null, null, null, null)
    }

    @Test
    void shouldReturnNullWhenCorrectEmailCodeProcessed() {
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
                        pair("notification-type", VERIFY_EMAIL.name()),
                        pair(
                                "account-recovery",
                                emailNotificationType.equals(
                                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES)));
    }


}
