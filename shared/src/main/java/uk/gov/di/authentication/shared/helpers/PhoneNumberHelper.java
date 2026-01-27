package uk.gov.di.authentication.shared.helpers;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Optional;

public class PhoneNumberHelper {

    private static final Logger LOG = LogManager.getLogger(PhoneNumberHelper.class);
    private static final String UK_COUNTRY_CODE = "44";

    public static String formatPhoneNumber(String phoneNumber) {
        var phoneUtil = PhoneNumberUtil.getInstance();
        try {
            var parsedPhoneNumber = phoneUtil.parse(phoneNumber, "GB");
            return phoneUtil.format(parsedPhoneNumber, PhoneNumberUtil.PhoneNumberFormat.E164);
        } catch (NumberParseException e) {
            LOG.warn("Error when trying to parse phone number");
            throw new RuntimeException(e);
        }
    }

    public static String getCountry(String phoneNumber) {
        try {
            return Integer.toString(
                    PhoneNumberUtil.getInstance().parse(phoneNumber, "GB").getCountryCode());
        } catch (NumberParseException e) {
            LOG.warn("Error when trying to parse phone number");
            throw new RuntimeException(e);
        }
    }

    public static Optional<String> maybeGetCountry(String phoneNumber) {
        try {
            return Optional.of(getCountry(phoneNumber));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public static String removeWhitespaceFromPhoneNumber(String phoneNumber) {
        return phoneNumber.replaceAll("\\s+", "");
    }

    public static boolean isDomesticPhoneNumber(String phoneNumber) {
        return maybeGetCountry(phoneNumber).map(UK_COUNTRY_CODE::equals).orElse(false);
    }
}
