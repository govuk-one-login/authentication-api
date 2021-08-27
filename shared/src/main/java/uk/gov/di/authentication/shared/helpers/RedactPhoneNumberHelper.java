package uk.gov.di.authentication.shared.helpers;

public class RedactPhoneNumberHelper {

    public static String redactPhoneNumber(String phoneNumber) {
        String substring = phoneNumber.substring(phoneNumber.length() - 4);
        String newString = phoneNumber.substring(0, phoneNumber.length() - 4);
        String concat = "*".repeat(newString.length());
        return concat + substring;
    }
}
