package uk.gov.di.orchestration.shared.api;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.openid.connect.sdk.Prompt;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;
import java.util.HashMap;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

public class FrontEndPages {

    private final URI frontEndBaseUri;

    private static final String PRIVACY_NOTICE = "privacy-notice";
    private static final String TERMS_OF_SERVICE = "terms-and-conditions";
    private static final String IPV_CALLBACK = "ipv-callback";
    private static final String AUTHORIZE = "authorize";
    private static final String ACCOUNT_BLOCKED = "unavailable-permanent";
    private static final String ACCOUNT_SUSPENDED = "unavailable-temporary";
    private static final String DEFAULT_LOGOUT = "signed-out";
    private static final String ERROR = "error";
    private static final String ERROR_IPV_CALLBACK = "ipv-callback-session-expiry-error";
    private static final String PROMPT_PARAMETER_KEY = "prompt";
    private static final String ERROR_CODE_PARAMETER_KEY = "error_code";
    private static final String ERROR_DESCRIPTION_PARAMETER_KEY = "error_description";
    private static final String GOOGLE_ANALYTICS_QUERY_PARAMETER_KEY = "result";

    public FrontEndPages(ConfigurationService configurationService) {
        frontEndBaseUri = configurationService.getFrontendBaseURL();
    }

    public URI baseURI() {
        return buildURI(frontEndBaseUri);
    }

    public URI privacyNoticeURI() {
        return buildURI(frontEndBaseUri, PRIVACY_NOTICE);
    }

    public URI termsOfServiceURI() {
        return buildURI(frontEndBaseUri, TERMS_OF_SERVICE);
    }

    public URI ipvCallbackURI() {
        return buildURI(frontEndBaseUri, IPV_CALLBACK);
    }

    public URI authorizeURI(Optional<Prompt.Type> prompt, Optional<String> googleAnalytics) {
        var queryParameters = new HashMap<String, String>();
        prompt.ifPresent(p -> queryParameters.put(PROMPT_PARAMETER_KEY, p.toString()));
        googleAnalytics.ifPresent(
                s -> queryParameters.put(GOOGLE_ANALYTICS_QUERY_PARAMETER_KEY, s));

        return buildURI(frontEndBaseUri, AUTHORIZE, queryParameters);
    }

    public URI logoutURI(Optional<ErrorObject> error) {
        var queryParameters = new HashMap<String, String>();
        error.ifPresent(
                e -> {
                    queryParameters.put(ERROR_CODE_PARAMETER_KEY, e.getCode());
                    queryParameters.put(ERROR_DESCRIPTION_PARAMETER_KEY, e.getDescription());
                });

        return buildURI(frontEndBaseUri, DEFAULT_LOGOUT, queryParameters);
    }

    public URI accountBlockedURI() {
        return buildURI(frontEndBaseUri, ACCOUNT_BLOCKED);
    }

    public URI accountSuspendedURI() {
        return buildURI(frontEndBaseUri, ACCOUNT_SUSPENDED);
    }

    public URI errorURI() {
        return buildURI(frontEndBaseUri, ERROR);
    }

    public URI errorIpvCallbackURI() {
        return buildURI(frontEndBaseUri, ERROR_IPV_CALLBACK);
    }
}
