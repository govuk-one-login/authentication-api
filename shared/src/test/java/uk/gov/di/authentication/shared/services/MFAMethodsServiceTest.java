package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.BACKUP_AUTH_APP_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DEFAULT_AUTH_APP_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DEFAULT_SMS_METHOD;

public class MFAMethodsServiceTest {
    @Nested
    class GetMfaMethodOrDefault {
        @Test
        void shouldReturnDefaultMFAMethodIfNoIdProvided() {
            Optional<MFAMethod> maybeDefaultMfaMethod =
                    MFAMethodsService.getMfaMethodOrDefaultMfaMethod(
                            List.of(DEFAULT_SMS_METHOD), null, null);
            assertTrue(maybeDefaultMfaMethod.isPresent());
            assertEquals(DEFAULT_SMS_METHOD, maybeDefaultMfaMethod.get());
        }

        @Test
        void shouldFilterOnMfaMethodType() {
            List<MFAMethod> mfaMethods = List.of(DEFAULT_AUTH_APP_METHOD, DEFAULT_SMS_METHOD);

            Optional<MFAMethod> maybeDefaultMfaMethod =
                    MFAMethodsService.getMfaMethodOrDefaultMfaMethod(
                            mfaMethods, null, MFAMethodType.SMS);
            assertTrue(maybeDefaultMfaMethod.isPresent());
            assertEquals(DEFAULT_SMS_METHOD, maybeDefaultMfaMethod.get());

            maybeDefaultMfaMethod =
                    MFAMethodsService.getMfaMethodOrDefaultMfaMethod(
                            mfaMethods, null, MFAMethodType.AUTH_APP);
            assertTrue(maybeDefaultMfaMethod.isPresent());
            assertEquals(DEFAULT_AUTH_APP_METHOD, maybeDefaultMfaMethod.get());
        }

        @Test
        void shouldReturnIdentifiedMfaIfPresent() {
            List<MFAMethod> mfaMethods = List.of(BACKUP_AUTH_APP_METHOD, DEFAULT_SMS_METHOD);
            Optional<MFAMethod> maybeDefaultMfaMethod =
                    MFAMethodsService.getMfaMethodOrDefaultMfaMethod(
                            mfaMethods, BACKUP_AUTH_APP_METHOD.getMfaIdentifier(), null);
            assertTrue(maybeDefaultMfaMethod.isPresent());
            assertEquals(BACKUP_AUTH_APP_METHOD, maybeDefaultMfaMethod.get());
        }

        @Test
        void shouldReturnEmptyIfIdentifiedMfaIsNotPresent() {
            List<MFAMethod> mfaMethods = List.of(DEFAULT_SMS_METHOD);
            Optional<MFAMethod> maybeDefaultMfaMethod =
                    MFAMethodsService.getMfaMethodOrDefaultMfaMethod(
                            mfaMethods, BACKUP_AUTH_APP_METHOD.getMfaIdentifier(), null);
            assertTrue(maybeDefaultMfaMethod.isEmpty());
        }
    }
}
