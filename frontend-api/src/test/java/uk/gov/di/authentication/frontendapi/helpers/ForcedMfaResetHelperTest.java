package uk.gov.di.authentication.frontendapi.helpers;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaResetType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DEFAULT_AUTH_APP_METHOD;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DEFAULT_SMS_METHOD;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER;

class ForcedMfaResetHelperTest {

    private static final MFAMethod INTERNATIONAL_SMS_METHOD =
            new MFAMethod(DEFAULT_SMS_METHOD).withDestination(INTERNATIONAL_MOBILE_NUMBER);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuditContext auditContext = AuditContext.emptyAuditContext();

    @Nested
    class IsInitiatedTest {

        private static final List<MFAMethod> INTERNATIONAL_SMS_METHODS =
                List.of(INTERNATIONAL_SMS_METHOD);
        private static final List<MFAMethod> UK_SMS_METHODS = List.of(DEFAULT_SMS_METHOD);

        static Stream<JourneyType> validJourneyTypes() {
            return Stream.of(
                    JourneyType.SIGN_IN,
                    JourneyType.REAUTHENTICATION,
                    JourneyType.PASSWORD_RESET_MFA);
        }

        @ParameterizedTest
        @MethodSource("validJourneyTypes")
        void shouldReturnTrueWhenAllConditionsMet(JourneyType journeyType) {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            assertTrue(
                    ForcedMfaResetHelper.isInitiated(
                            configurationService, INTERNATIONAL_SMS_METHODS, journeyType));
        }

        @Test
        void shouldReturnFalseWhenFeatureFlagDisabled() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(false);

            assertFalse(
                    ForcedMfaResetHelper.isInitiated(
                            configurationService, INTERNATIONAL_SMS_METHODS, JourneyType.SIGN_IN));
        }

        @Test
        void shouldReturnFalseWhenPhoneNumberIsDomestic() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            assertFalse(
                    ForcedMfaResetHelper.isInitiated(
                            configurationService, UK_SMS_METHODS, JourneyType.SIGN_IN));
        }

        @ParameterizedTest
        @EnumSource(
                value = JourneyType.class,
                names = {"SIGN_IN", "REAUTHENTICATION", "PASSWORD_RESET_MFA"},
                mode = EnumSource.Mode.EXCLUDE)
        void shouldReturnFalseForInvalidJourneyTypes(JourneyType journeyType) {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            assertFalse(
                    ForcedMfaResetHelper.isInitiated(
                            configurationService, INTERNATIONAL_SMS_METHODS, journeyType));
        }

        @Test
        void shouldReturnFalseWhenMfaMethodsListIsEmpty() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            assertFalse(
                    ForcedMfaResetHelper.isInitiated(
                            configurationService, List.of(), JourneyType.SIGN_IN));
        }
    }

    @Nested
    class EmitRequestedAuditEventTest {
        @Test
        void shouldEmitAuditEventWithExpectedInternationalNumberMetadata() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            ForcedMfaResetHelper.emitRequestedAuditEvent(
                    auditService,
                    JourneyType.SIGN_IN,
                    Optional.of(INTERNATIONAL_SMS_METHOD),
                    auditContext);

            verify(auditService)
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                            eq(auditContext.withPhoneNumber(INTERNATIONAL_MOBILE_NUMBER)),
                            eq(pair(AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE, "7")),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE,
                                            MfaResetType.FORCED_INTERNATIONAL_NUMBERS)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                            JourneyType.ACCOUNT_RECOVERY)));
        }

        @Test
        void shouldEmitAuditEventWithUnknownPhoneWhenActiveMfaMethodIsNotSms() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            ForcedMfaResetHelper.emitRequestedAuditEvent(
                    auditService,
                    JourneyType.SIGN_IN,
                    Optional.of(DEFAULT_AUTH_APP_METHOD),
                    auditContext);

            verify(auditService)
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                            eq(auditContext.withPhoneNumber(AuditService.UNKNOWN)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE,
                                            AuditService.UNKNOWN)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE,
                                            MfaResetType.FORCED_INTERNATIONAL_NUMBERS)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                            JourneyType.ACCOUNT_RECOVERY)));
        }

        @Test
        void shouldEmitAuditEventWithUnknownPhoneWhenActiveMfaMethodIsEmpty() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            ForcedMfaResetHelper.emitRequestedAuditEvent(
                    auditService, JourneyType.SIGN_IN, Optional.empty(), auditContext);

            verify(auditService)
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                            eq(auditContext.withPhoneNumber(AuditService.UNKNOWN)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE,
                                            AuditService.UNKNOWN)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE,
                                            MfaResetType.FORCED_INTERNATIONAL_NUMBERS)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                            JourneyType.ACCOUNT_RECOVERY)));
        }
    }
}
