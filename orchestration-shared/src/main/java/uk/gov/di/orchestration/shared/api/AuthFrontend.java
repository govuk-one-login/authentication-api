package uk.gov.di.orchestration.shared.api;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.openid.connect.sdk.Prompt;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

public class AuthFrontend implements CommonFrontend {

    private final URI frontendBaseUri;

    public AuthFrontend(ConfigurationService configurationService) {
        frontendBaseUri = configurationService.getAuthFrontendBaseURL();
    }

    public URI baseURI() {
        return frontendBaseUri;
    }

    public URI privacyNoticeURI() {
        return buildURI(frontendBaseUri, "privacy-notice");
    }

    public URI termsOfServiceURI() {
        return buildURI(frontendBaseUri, "terms-and-conditions");
    }

    public URI ipvCallbackURI() {
        return buildURI(frontendBaseUri, "ipv/callback/authorize");
    }

    public URI authorizeURI(Optional<Prompt.Type> prompt, Optional<String> googleAnalytics) {
        var queryParameters = new HashMap<String, String>();
        prompt.ifPresent(p -> queryParameters.put("prompt", p.toString()));
        googleAnalytics.ifPresent(s -> queryParameters.put("result", s));

        return buildURI(frontendBaseUri, "authorize", queryParameters);
    }

    public URI defaultLogoutURI() {
        return buildURI(frontendBaseUri, "signed-out");
    }

    public URI errorLogoutURI(ErrorObject error) {
        var queryParameters =
                Map.of(
                        "error_code", error.getCode(),
                        "error_description", error.getDescription());

        return buildURI(defaultLogoutURI(), queryParameters);
    }

    public URI accountBlockedURI() {
        return buildURI(frontendBaseUri, "unavailable-permanent");
    }

    public URI accountSuspendedURI() {
        return buildURI(frontendBaseUri, "unavailable-temporary");
    }

    public URI errorURI() {
        return buildURI(frontendBaseUri, "error");
    }

    public URI errorIpvCallbackURI() {
        return buildURI(frontendBaseUri, "ipv-callback-session-expiry-error");
    }
}
