package uk.gov.di.authentication.frontendapi.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaResetType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"SIGN_IN", "PASSWORD_RESET_MFA", "REAUTHENTICATION"})
    void shouldEmitAuditEventForIncludedJourneyWithInternationalNumber(JourneyType journeyType) {
        when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

        ForcedMfaResetHelper.emitForcedMfaResetAuditEventIfRequired(
                configurationService,
                auditService,
                journeyType,
                List.of(INTERNATIONAL_SMS_METHOD),
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

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"REGISTRATION", "PASSWORD_RESET", "ACCOUNT_RECOVERY", "ACCOUNT_MANAGEMENT"})
    void shouldNotEmitAuditEventForExcludedJourneyTypes(JourneyType journeyType) {
        when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

        ForcedMfaResetHelper.emitForcedMfaResetAuditEventIfRequired(
                configurationService,
                auditService,
                journeyType,
                List.of(INTERNATIONAL_SMS_METHOD),
                Optional.of(INTERNATIONAL_SMS_METHOD),
                auditContext);

        verifyNoAuditEvent();
    }

    @Test
    void shouldNotEmitAuditEventWhenFeatureFlagDisabled() {
        when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(false);

        ForcedMfaResetHelper.emitForcedMfaResetAuditEventIfRequired(
                configurationService,
                auditService,
                JourneyType.SIGN_IN,
                List.of(INTERNATIONAL_SMS_METHOD),
                Optional.of(INTERNATIONAL_SMS_METHOD),
                auditContext);

        verifyNoAuditEvent();
    }

    @Test
    void shouldNotEmitAuditEventForDomesticNumber() {
        when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

        ForcedMfaResetHelper.emitForcedMfaResetAuditEventIfRequired(
                configurationService,
                auditService,
                JourneyType.SIGN_IN,
                List.of(DEFAULT_SMS_METHOD),
                Optional.of(DEFAULT_SMS_METHOD),
                auditContext);

        verifyNoAuditEvent();
    }

    @Test
    void shouldEmitWithUnknownPhoneWhenActiveMfaMethodIsNotSms() {
        when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

        ForcedMfaResetHelper.emitForcedMfaResetAuditEventIfRequired(
                configurationService,
                auditService,
                JourneyType.SIGN_IN,
                List.of(DEFAULT_AUTH_APP_METHOD, INTERNATIONAL_SMS_METHOD),
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
    void shouldEmitWithUnknownPhoneWhenActiveMfaMethodIsEmpty() {
        when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

        ForcedMfaResetHelper.emitForcedMfaResetAuditEventIfRequired(
                configurationService,
                auditService,
                JourneyType.SIGN_IN,
                List.of(INTERNATIONAL_SMS_METHOD),
                Optional.empty(),
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

    private void verifyNoAuditEvent() {
        verify(auditService, never())
                .submitAuditEvent(
                        eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                        any(AuditContext.class),
                        any(AuditService.MetadataPair[].class));
    }
}
