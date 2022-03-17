package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ErrorResponse;

import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ValidationHelperTest {

    private static Stream<String> invalidPhoneNumbers() {
        return Stream.of(
                "0123456789A", "0123456789", "012345678999", "01234567891", "202-456-1111");
    }

    @ParameterizedTest
    @MethodSource("invalidPhoneNumbers")
    void shouldReturnErrorIfMobileNumberIsInvalid(String phoneNumber) {
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1012),
                ValidationHelper.validatePhoneNumber(phoneNumber));
    }

    private static Stream<String> internationalPhoneNumbers() {
        return Stream.of(
                "+447316763843",
                "+4407316763843",
                "+33645453322",
                "+330645453322",
                "+447316763843",
                "+447316763843",
                "+33645453322",
                "+33645453322");
    }

    @ParameterizedTest
    @MethodSource("internationalPhoneNumbers")
    void shouldAcceptValidInternationPhoneNumbers(String phoneNumber) {
        assertThat(ValidationHelper.validatePhoneNumber(phoneNumber), equalTo(Optional.empty()));
    }

    @Test
    void shouldAcceptValidBritishPhoneNumbers() {
        assertThat(ValidationHelper.validatePhoneNumber("07911123456"), equalTo(Optional.empty()));
    }

    private static Stream<Arguments> invalidPasswords() {
        return Stream.of(
                Arguments.of("", ErrorResponse.ERROR_1005),
                Arguments.of(null, ErrorResponse.ERROR_1005),
                Arguments.of("passw0r", ErrorResponse.ERROR_1006));
    }

    @ParameterizedTest
    @MethodSource("invalidPasswords")
    void shouldRejectInvalidPasswords(String password, ErrorResponse expectedResponse) {
        assertEquals(Optional.of(expectedResponse), ValidationHelper.validatePassword(password));
    }

    private static Stream<String> validPasswords() {
        return Stream.of("+pa?55worD", "computer-1", "passsssssssssssswwwwoooordddd-2");
    }

    @ParameterizedTest
    @MethodSource("validPasswords")
    void shouldAcceptValidPassword(String password) {
        assertEquals(Optional.empty(), ValidationHelper.validatePassword(password));
    }
}
