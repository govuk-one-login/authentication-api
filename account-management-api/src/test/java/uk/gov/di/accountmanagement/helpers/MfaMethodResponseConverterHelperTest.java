package uk.gov.di.accountmanagement.helpers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.response.MfaMethodResponse;
import uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.accountmanagement.helpers.MfaMethodResponseConverterHelper.convertMfaMethodsToMfaMethodResponse;
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
            MfaMethodResponse.smsMethodData(
                    DEFAULT_SMS_MFA_IDENTIFIER, DEFAULT, true, PHONE_NUMBER);
    private static final MFAMethod DEFAULT_AUTH_APP_MFA_METHOD =
            MFAMethod.authAppMfaMethod(
                    AUTH_APP_CREDENTIAL, true, true, DEFAULT, DEFAULT_AUTH_APP_MFA_IDENTIFIER);
    private static final MfaMethodResponse DEFAULT_AUTH_APP_MFA_AS_MFA_METHOD_RESPONSE =
            MfaMethodResponse.authAppMfaData(
                    DEFAULT_AUTH_APP_MFA_IDENTIFIER, DEFAULT, true, AUTH_APP_CREDENTIAL);
    private static final MFAMethod BACKUP_AUTH_APP_MFA_METHOD =
            MFAMethod.authAppMfaMethod(
                    AUTH_APP_CREDENTIAL_2, true, true, BACKUP, BACKUP_AUTH_APP_MFA_IDENTIFIER);
    private static final MfaMethodResponse BACKUP_AUTH_APP_MFA_AS_MFA_METHOD_RESPONSE =
            MfaMethodResponse.authAppMfaData(
                    BACKUP_AUTH_APP_MFA_IDENTIFIER, BACKUP, true, AUTH_APP_CREDENTIAL_2);

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
    void shouldSuccessfullyConvertMfaMethodsToReponses(
            List<MFAMethod> mfaMethods, List<MfaMethodResponse> expectedResponses) {
        var convertedResult = convertMfaMethodsToMfaMethodResponse(mfaMethods);

        var expectedResult = Result.success(expectedResponses);

        assertEquals(expectedResult, convertedResult);
    }

    private static Stream<List<MFAMethod>> methodsIncludingInvalidMfa() {
        var invalidMfaMethod =
                new MFAMethod("not a valid mfa type", null, true, true, "updated-at");
        return Stream.of(
                List.of(invalidMfaMethod),
                List.of(invalidMfaMethod, SMS_MFA_METHOD),
                List.of(SMS_MFA_METHOD, invalidMfaMethod),
                List.of(SMS_MFA_METHOD, BACKUP_AUTH_APP_MFA_METHOD, invalidMfaMethod));
    }

    @ParameterizedTest
    @MethodSource("methodsIncludingInvalidMfa")
    void shouldReturnAnErrorIfAnyMethodsFailToConvert(
            List<MFAMethod> mfaMethodsIncludingUncovertableMfaMethod) {
        var convertedResult =
                convertMfaMethodsToMfaMethodResponse(mfaMethodsIncludingUncovertableMfaMethod);

        assertEquals(
                Result.failure(
                        MfaRetrieveFailureReason.ERROR_CONVERTING_MFA_METHOD_TO_MFA_METHOD_DATA),
                convertedResult);
    }
}
