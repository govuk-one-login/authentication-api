package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.exceptions.CodeRequestTypeNotFoundException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;

class CodeRequestTypeTest {

    @Test
    void invalidNotificationTypeJourneyComboShouldThrowError() {
        assertThrows(
                CodeRequestTypeNotFoundException.class,
                () -> CodeRequestType.getCodeRequestType(VERIFY_EMAIL, JourneyType.SIGN_IN));
    }
}
