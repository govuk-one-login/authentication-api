package uk.gov.di.orchestration.shared.api;

import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;

import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

public class OidcAPI {

    private final URI oidcApiBseUrl;

    public OidcAPI(ConfigurationService configurationService) {
        oidcApiBseUrl = configurationService.getOidcApiBaseURL();
    }

    public URI baseURI() {
        return oidcApiBseUrl;
    }

    public URI trustmarkURI() {
        return buildURI(oidcApiBseUrl, "trustmark");
    }

    public URI wellKnownURI() {
        return buildURI(oidcApiBseUrl, ".well-known/jwks.json");
    }

    public URI tokenURI() {
        return buildURI(oidcApiBseUrl, "token");
    }

    public URI userInfoURI() {
        return buildURI(oidcApiBseUrl, "userinfo");
    }

    public URI authorizeURI() {
        return buildURI(oidcApiBseUrl, "authorize");
    }

    public URI registerationURI() {
        return buildURI(oidcApiBseUrl, "connect/register");
    }

    public URI logoutURI() {
        return buildURI(oidcApiBseUrl, "logout");
    }
}
