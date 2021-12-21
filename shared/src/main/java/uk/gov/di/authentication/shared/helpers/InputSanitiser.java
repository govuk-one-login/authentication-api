package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Base64;
import java.util.Optional;

public class InputSanitiser {

    private static final Logger LOG = LogManager.getLogger();

    public static Optional<String> sanitiseBase64(String input) {
        try {
            Base64.getUrlDecoder().decode(input);

        } catch (IllegalArgumentException e) {
            LOG.warn("Unsafe base64 input");
            return Optional.empty();
        }

        return Optional.of(input);
    }
}
