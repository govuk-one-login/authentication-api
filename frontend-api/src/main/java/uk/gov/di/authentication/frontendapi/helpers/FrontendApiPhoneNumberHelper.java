package uk.gov.di.authentication.frontendapi.helpers;

import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

public class FrontendApiPhoneNumberHelper {
    public static final int NUMBER_OF_LAST_DIGITS = 3;

    public static String redactPhoneNumber(String phoneNumber) {
        String substring = phoneNumber.substring(phoneNumber.length() - 4);
        String newString = phoneNumber.substring(0, phoneNumber.length() - 4);
        String concat = "*".repeat(newString.length());
        return concat + substring;
    }

    public static String getLastDigitsOfPhoneNumber(UserMfaDetail userMfaDetail) {
        if (userMfaDetail.phoneNumber() != null
                && !userMfaDetail.phoneNumber().isEmpty()
                && userMfaDetail.phoneNumber().length() >= NUMBER_OF_LAST_DIGITS
                && MFAMethodType.SMS.equals(userMfaDetail.mfaMethodType())) {
            return userMfaDetail
                    .phoneNumber()
                    .substring(userMfaDetail.phoneNumber().length() - NUMBER_OF_LAST_DIGITS);
        } else {
            return null;
        }
    }
}
