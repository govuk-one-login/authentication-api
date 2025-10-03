package uk.gov.di.authentication.frontendapi.helpers;

import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

public class FrontendApiPhoneNumberHelper {
    public static final int NUMBER_OF_LAST_DIGITS = 3;
    public static final int NUMBER_OF_UNREDACTED_DIGITS = 4;

    public static String redactPhoneNumber(String phoneNumber) {
        int redactLength = phoneNumber.length() - NUMBER_OF_UNREDACTED_DIGITS;
        return "*".repeat(redactLength) + phoneNumber.substring(redactLength);
    }

    public static String getLastDigitsOfPhoneNumber(UserMfaDetail userMfaDetail) {
        if (userMfaDetail.phoneNumber() != null
                && !userMfaDetail.phoneNumber().isEmpty()
                && MFAMethodType.SMS.equals(userMfaDetail.mfaMethodType())) {
            return getLastDigitsOfPhoneNumber(userMfaDetail.phoneNumber());
        } else {
            return null;
        }
    }

    public static String getLastDigitsOfPhoneNumber(String phoneNumber) {
        if (phoneNumber != null && phoneNumber.length() >= NUMBER_OF_LAST_DIGITS) {
            return phoneNumber.substring(phoneNumber.length() - NUMBER_OF_LAST_DIGITS);
        } else {
            return null;
        }
    }
}
