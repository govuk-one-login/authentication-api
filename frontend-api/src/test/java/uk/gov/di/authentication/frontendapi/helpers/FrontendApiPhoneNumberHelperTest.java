package uk.gov.di.authentication.frontendapi.helpers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethodType;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper.getLastDigitsOfPhoneNumber;

class FrontendApiPhoneNumberHelperTest {

    @ParameterizedTest
    @MethodSource("userMfaDetail")
    void shouldReturnLastThreeDigitsOfPhoneNumber(UserMfaDetail userMfaDetail, String lastDigits) {
        var result = getLastDigitsOfPhoneNumber(userMfaDetail);
        assertThat(result, equalTo(lastDigits));
    }

    private static Stream<Arguments> userMfaDetail() {
        return Stream.of(
                Arguments.of(UserMfaDetail.noMfa(), null),
                Arguments.of(new UserMfaDetail(false, false, MFAMethodType.SMS, ""), null),
                Arguments.of(
                        new UserMfaDetail(false, false, MFAMethodType.AUTH_APP, "123456789"), null),
                Arguments.of(
                        new UserMfaDetail(false, false, MFAMethodType.SMS, "123456789"), "789"),
                Arguments.of(new UserMfaDetail(false, false, MFAMethodType.SMS, "12"), null));
    }
}
