package uk.gov.di.authentication.frontendapi.helpers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.mfa.AuthAppMfaMethodResponse;
import uk.gov.di.authentication.frontendapi.entity.mfa.MfaMethodResponse;
import uk.gov.di.authentication.frontendapi.entity.mfa.SmsMfaMethodResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper.redactPhoneNumber;
import static uk.gov.di.authentication.frontendapi.helpers.MfaMethodResponseConverterHelper.convertMfaMethodsToMfaMethodResponse;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;

class MfaMethodResponseConverterHelperTest {
    private static final String PHONE_NUMBER = "+447900000000";
    private static final String DEFAULT_SMS_MFA_IDENTIFIER = "f78f2603-bcc2-4602-9897-d9ea76a343c7";
    private static final String DEFAULT_AUTH_APP_MFA_IDENTIFIER =
            "3c7a7f92-006f-4ab8-b3ae-4ce1032df9dd";
    private static final String BACKUP_AUTH_APP_MFA_IDENTIFIER =
            "a1bbb03d-5f3e-4b3f-9439-46e648c3d892";
    private static final String AUTH_APP_CREDENTIAL = "some-credential";
    private static final String AUTH_APP_CREDENTIAL_2 = "another-credential";
    private static final MFAMethod SMS_MFA_METHOD =
            MFAMethod.smsMfaMethod(true, true, PHONE_NUMBER, DEFAULT, DEFAULT_SMS_MFA_IDENTIFIER);
    private static final MfaMethodResponse SMS_MFA_METHOD_AS_MFA_METHOD_RESPONSE =
            new SmsMfaMethodResponse(
                    DEFAULT_SMS_MFA_IDENTIFIER,
                    MFAMethodType.SMS,
                    DEFAULT,
                    redactPhoneNumber(PHONE_NUMBER));
    private static final MFAMethod DEFAULT_AUTH_APP_MFA_METHOD =
            MFAMethod.authAppMfaMethod(
                    AUTH_APP_CREDENTIAL, true, true, DEFAULT, DEFAULT_AUTH_APP_MFA_IDENTIFIER);
    private static final MfaMethodResponse DEFAULT_AUTH_APP_MFA_AS_MFA_METHOD_RESPONSE =
            new AuthAppMfaMethodResponse(
                    DEFAULT_AUTH_APP_MFA_IDENTIFIER, MFAMethodType.AUTH_APP, DEFAULT);
    private static final MFAMethod BACKUP_AUTH_APP_MFA_METHOD =
            MFAMethod.authAppMfaMethod(
                    AUTH_APP_CREDENTIAL_2, true, true, BACKUP, BACKUP_AUTH_APP_MFA_IDENTIFIER);
    private static final MfaMethodResponse BACKUP_AUTH_APP_MFA_AS_MFA_METHOD_RESPONSE =
            new AuthAppMfaMethodResponse(
                    BACKUP_AUTH_APP_MFA_IDENTIFIER, MFAMethodType.AUTH_APP, BACKUP);
    private static final String INVALID_MFA_TYPE = "not a valid mfa type";

    private static Stream<Arguments> convertableMethodsToExpectedMfaMethodResponses() {
        return Stream.of(
                Arguments.of(
                        List.of(SMS_MFA_METHOD), List.of(SMS_MFA_METHOD_AS_MFA_METHOD_RESPONSE)),
                Arguments.of(
                        List.of(DEFAULT_AUTH_APP_MFA_METHOD),
                        List.of(DEFAULT_AUTH_APP_MFA_AS_MFA_METHOD_RESPONSE)),
                Arguments.of(
                        List.of(SMS_MFA_METHOD, BACKUP_AUTH_APP_MFA_METHOD),
                        List.of(
                                SMS_MFA_METHOD_AS_MFA_METHOD_RESPONSE,
                                BACKUP_AUTH_APP_MFA_AS_MFA_METHOD_RESPONSE)));
    }

    @ParameterizedTest
    @MethodSource("convertableMethodsToExpectedMfaMethodResponses")
    void shouldSuccessfullyConvertMfaMethodsToResponses(
            List<MFAMethod> mfaMethods, List<MfaMethodResponse> expectedResponses) {
        var convertedResult = convertMfaMethodsToMfaMethodResponse(mfaMethods);

        var expectedResult = Result.success(expectedResponses);

        assertEquals(expectedResult, convertedResult);
    }

    private static Stream<List<MFAMethod>> methodsIncludingInvalidMfa() {
        var invalidMfaMethodType = new MFAMethod(INVALID_MFA_TYPE, null, true, true, "updated-at");
        var invalidMfaMethodPriority =
                new MFAMethod()
                        .withMfaMethodType(MFAMethodType.SMS.getValue())
                        .withMethodVerified(true)
                        .withEnabled(true)
                        .withDestination("destination")
                        .withPriority("invalid-priority")
                        .withMfaIdentifier("id");
        return Stream.of(
                List.of(invalidMfaMethodType),
                List.of(invalidMfaMethodType, SMS_MFA_METHOD),
                List.of(SMS_MFA_METHOD, invalidMfaMethodType),
                List.of(SMS_MFA_METHOD, BACKUP_AUTH_APP_MFA_METHOD, invalidMfaMethodType),
                List.of(invalidMfaMethodPriority, SMS_MFA_METHOD));
    }

    @ParameterizedTest
    @MethodSource("methodsIncludingInvalidMfa")
    void shouldReturnAnErrorIfAnyMethodsFailToConvert(
            List<MFAMethod> mfaMethodsIncludingUnconvertableMfaMethod) {
        var convertedResult =
                convertMfaMethodsToMfaMethodResponse(mfaMethodsIncludingUnconvertableMfaMethod);

        assertTrue(
                convertedResult
                        .getFailure()
                        .startsWith("Error converting mfa method to mfa method data"),
                "Failure string should start with the expected prefix");
    }
}
