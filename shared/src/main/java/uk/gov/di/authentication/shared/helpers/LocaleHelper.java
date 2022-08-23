package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage.CY;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage.EN;

public class LocaleHelper {

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
    }

    public static Optional<SupportedLanguage> getPrimaryLanguageFromUILocales(
            AuthenticationRequest authenticationRequest,
            ConfigurationService configurationService) {

        if (Objects.isNull(authenticationRequest.getUILocales())) {
            return Optional.empty();
        }
        for (LangTag langTag : authenticationRequest.getUILocales()) {
            if (langTag.getPrimaryLanguage().equals(EN.getLanguage())) {
                return Optional.of(EN);
            }
            if (configurationService.isLanguageEnabled(CY)
                    && langTag.getPrimaryLanguage().equals(SupportedLanguage.CY.getLanguage())) {
                return Optional.of(CY);
            }
        }
        return Optional.empty();
    }
}
