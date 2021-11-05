package uk.gov.di.authentication.shared.helpers;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PhoneNumberHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(PhoneNumberHelper.class);

    public static String formatPhoneNumber(String phoneNumber) {
        PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
        try {
            var parsedPhoneNumber = phoneUtil.parse(phoneNumber, "GB");
            return phoneUtil.format(parsedPhoneNumber, PhoneNumberUtil.PhoneNumberFormat.E164);
        } catch (NumberParseException e) {
            LOGGER.error("Error when trying to parse phone number");
            throw new RuntimeException(e);
        }
    }
}
