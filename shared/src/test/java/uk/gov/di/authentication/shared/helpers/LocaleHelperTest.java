package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;

class LocaleHelperTest {

    private static Optional<SupportedLanguage> PRIMARY_LANGUAGE_EN =
            Optional.of(SupportedLanguage.EN);
    private static Optional<SupportedLanguage> PRIMARY_LANGUAGE_CY =
            Optional.of(SupportedLanguage.CY);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private static Stream<Arguments> uiLocalesAndPrimaryLanguageCYEnabled()
            throws LangTagException {
        return Stream.of(
                Arguments.of(List.of(LangTag.parse("en")), PRIMARY_LANGUAGE_EN),
                Arguments.of(
                        List.of(LangTag.parse("en"), LangTag.parse("cy")), PRIMARY_LANGUAGE_EN),
                Arguments.of(
                        List.of(LangTag.parse("es"), LangTag.parse("en"), LangTag.parse("cy")),
                        PRIMARY_LANGUAGE_EN),
                Arguments.of(
                        List.of(LangTag.parse("es"), LangTag.parse("cy"), LangTag.parse("en")),
                        PRIMARY_LANGUAGE_CY),
                Arguments.of(List.of(LangTag.parse("cy")), PRIMARY_LANGUAGE_CY),
                Arguments.of(
                        List.of(LangTag.parse("cy"), LangTag.parse("en")), PRIMARY_LANGUAGE_CY),
                Arguments.of(List.of(), Optional.empty()),
                Arguments.of(
                        List.of(LangTag.parse("es"), LangTag.parse("fr"), LangTag.parse("ja")),
                        Optional.empty()),
                Arguments.of(
                        List.of(LangTag.parse("cy-AR"), LangTag.parse("en")), PRIMARY_LANGUAGE_CY),
                Arguments.of(
                        List.of(LangTag.parse("de-DE"), LangTag.parse("cy"), LangTag.parse("en")),
                        PRIMARY_LANGUAGE_CY),
                Arguments.of(
                        List.of(
                                LangTag.parse("zh-cmn-Hans-CN"),
                                LangTag.parse("en-US"),
                                LangTag.parse("cy")),
                        PRIMARY_LANGUAGE_EN));
    }

    private static Stream<Arguments> uiLocalesAndPrimaryLanguageCYNotEnabled()
            throws LangTagException {
        return Stream.of(
                Arguments.of(List.of(LangTag.parse("en")), PRIMARY_LANGUAGE_EN),
                Arguments.of(
                        List.of(LangTag.parse("en"), LangTag.parse("cy")), PRIMARY_LANGUAGE_EN),
                Arguments.of(
                        List.of(LangTag.parse("es"), LangTag.parse("en"), LangTag.parse("cy")),
                        PRIMARY_LANGUAGE_EN),
                Arguments.of(
                        List.of(LangTag.parse("es"), LangTag.parse("cy"), LangTag.parse("en")),
                        PRIMARY_LANGUAGE_EN),
                Arguments.of(List.of(LangTag.parse("cy")), Optional.empty()),
                Arguments.of(
                        List.of(LangTag.parse("cy"), LangTag.parse("en")), PRIMARY_LANGUAGE_EN),
                Arguments.of(List.of(), Optional.empty()),
                Arguments.of(
                        List.of(LangTag.parse("es"), LangTag.parse("fr"), LangTag.parse("ja")),
                        Optional.empty()),
                Arguments.of(
                        List.of(LangTag.parse("cy-AR"), LangTag.parse("en")), PRIMARY_LANGUAGE_EN),
                Arguments.of(
                        List.of(LangTag.parse("de-DE"), LangTag.parse("cy"), LangTag.parse("en")),
                        PRIMARY_LANGUAGE_EN),
                Arguments.of(
                        List.of(
                                LangTag.parse("zh-cmn-Hans-CN"),
                                LangTag.parse("en-US"),
                                LangTag.parse("cy")),
                        PRIMARY_LANGUAGE_EN));
    }

    @ParameterizedTest
    @MethodSource("uiLocalesAndPrimaryLanguageCYEnabled")
    void shouldReturnLanguageBasedOnUILocalesCYEnabled(
            List<LangTag> uiLocales, Optional<SupportedLanguage> primaryLanguage)
            throws LangTagException {
        when(configurationService.isLanguageEnabled(SupportedLanguage.CY)).thenReturn(true);
        assertThat(
                LocaleHelper.getPrimaryLanguageFromUILocales(
                        generateAuthRequest(uiLocales), configurationService),
                equalTo(primaryLanguage));
    }

    @ParameterizedTest
    @MethodSource("uiLocalesAndPrimaryLanguageCYNotEnabled")
    void shouldReturnLanguageBasedOnUILocalesCYNotEnabled(
            List<LangTag> uiLocales, Optional<SupportedLanguage> primaryLanguage)
            throws LangTagException {
        when(configurationService.isLanguageEnabled(SupportedLanguage.CY)).thenReturn(false);
        assertThat(
                LocaleHelper.getPrimaryLanguageFromUILocales(
                        generateAuthRequest(uiLocales), configurationService),
                equalTo(primaryLanguage));
    }

    private AuthenticationRequest generateAuthRequest(List<LangTag> uiLocales) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(),
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce());
        builder.uiLocales(uiLocales);
        return builder.build();
    }
}
