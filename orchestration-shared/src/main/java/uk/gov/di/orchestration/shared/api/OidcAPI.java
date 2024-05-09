package uk.gov.di.orchestration.shared.api;

import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;

import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

public class OidcAPI {

    private final URI oidcApiBseUrl;
    private static final String TRUSTMARK_ENDPOINT = "trustmark";
    private static final String WELL_KNOWN_ENDPOINT = ".well-known/jwks.json";
    private static final String TOKEN_ENDPOINT = "token";
    private static final String USER_INFO_ENDPOINT = "userinfo";
    private static final String AUTHORIZE_ENDPOINT = "authorize";
    private static final String REGISTER_ENDPOINT = "connect/register";
    private static final String LOGOUT = "logout";

    public OidcAPI(ConfigurationService configurationService) {
        oidcApiBseUrl = configurationService.getOidcApiBaseURL();
    }

    public URI baseURI() {
        return buildURI(oidcApiBseUrl);
    }

    public URI trustmarkURI() {
        return buildURI(oidcApiBseUrl, TRUSTMARK_ENDPOINT);
    }

    public URI wellKnownURI() {
        return buildURI(oidcApiBseUrl, WELL_KNOWN_ENDPOINT);
    }

    public URI tokenURI() {
        return buildURI(oidcApiBseUrl, TOKEN_ENDPOINT);
    }

    public URI userInfoURI() {
        return buildURI(oidcApiBseUrl, USER_INFO_ENDPOINT);
    }

    public URI authorizeURI() {
        return buildURI(oidcApiBseUrl, AUTHORIZE_ENDPOINT);
    }

    public URI registerationURI() {
        return buildURI(oidcApiBseUrl, REGISTER_ENDPOINT);
    }

    public URI logoutURI() {
        return buildURI(oidcApiBseUrl, LOGOUT);
    }
}
