package uk.gov.di.orchestration.shared.api;

import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;

import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

public class OidcAPI {

    private final URI oidcApiBaseUrl;

    public OidcAPI(ConfigurationService configurationService) {
        oidcApiBaseUrl = configurationService.getOidcApiBaseURL();
    }

    public URI baseURI() {
        return oidcApiBaseUrl;
    }

    public URI getIssuerURI() {
        return buildURI(oidcApiBaseUrl);
    }

    public URI trustmarkURI() {
        return buildURI(oidcApiBaseUrl, "trustmark");
    }

    public URI wellKnownURI() {
        return buildURI(oidcApiBaseUrl, ".well-known/jwks.json");
    }

    public URI tokenURI() {
        return buildURI(oidcApiBaseUrl, "token");
    }

    public URI userInfoURI() {
        return buildURI(oidcApiBaseUrl, "userinfo");
    }

    public URI authorizeURI() {
        return buildURI(oidcApiBaseUrl, "authorize");
    }

    public URI registerationURI() {
        return buildURI(oidcApiBaseUrl, "connect/register");
    }

    public URI logoutURI() {
        return buildURI(oidcApiBaseUrl, "logout");
    }
}
