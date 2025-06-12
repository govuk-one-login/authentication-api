package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.USER_LANGUAGE_HEADER;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class LocaleHelper {

    private static final Logger LOG = LogManager.getLogger(LocaleHelper.class);

    public enum SupportedLanguage {
        EN("en"),

        CY("cy");

        private String language;

        SupportedLanguage(String language) {
            this.language = language;
        }

        public String getLanguage() {
            return language;
        }

        @Override
        public String toString() {
            return language;
        }
    }

    public static Optional<SupportedLanguage> getPrimaryLanguageFromUILocales(
            AuthenticationRequest authenticationRequest,
            ConfigurationService configurationService) {

        if (Objects.isNull(authenticationRequest.getUILocales())) {
            return Optional.empty();
        }
        LOG.info("ui_locales is present: {}", authenticationRequest.getUILocales());
        for (LangTag langTag : authenticationRequest.getUILocales()) {
            if (langTag.getPrimaryLanguage().equalsIgnoreCase(SupportedLanguage.EN.getLanguage())) {
                return Optional.of(SupportedLanguage.EN);
            } else if (langTag.getPrimaryLanguage()
                    .equalsIgnoreCase(SupportedLanguage.CY.getLanguage())) {
                return Optional.of(SupportedLanguage.CY);
            }
        }
        return Optional.empty();
    }

    public static SupportedLanguage matchSupportedLanguage(Optional<String> language) {
        return language.map(
                        lng -> {
                            if (lng.equalsIgnoreCase(SupportedLanguage.CY.getLanguage())) {
                                return SupportedLanguage.CY;
                            } else {
                                return SupportedLanguage.EN;
                            }
                        })
                .orElseGet(() -> SupportedLanguage.EN);
    }

    public static Optional<String> getUserLanguageFromRequestHeaders(
            Map<String, String> headers, ConfigurationService configurationService) {
        Optional<String> userLanguage =
                getOptionalHeaderValueFromHeaders(
                        headers,
                        USER_LANGUAGE_HEADER,
                        configurationService.getHeadersCaseInsensitive());

        return userLanguage.flatMap(InputSanitiser::sanitiseBase64);
    }
}
