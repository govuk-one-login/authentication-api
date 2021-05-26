package uk.gov.di.resources;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import uk.gov.di.configuration.AuthenticationApiConfiguration;
import uk.gov.di.services.TokenService;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

@Path("/.well-known/")
public class WellKnownResource {

    private TokenService tokenService;
    private AuthenticationApiConfiguration configuration;

    public WellKnownResource(TokenService tokenService, AuthenticationApiConfiguration configuration) {
        this.tokenService = tokenService;
        this.configuration = configuration;
    }

    @GET
    @Path("/openid-configuration")
    @Produces("application/json")
    public String openIdConfiguration() throws URISyntaxException {
        var providerMetadata = new OIDCProviderMetadata(new Issuer(this.configuration.getBaseUrl()),
                List.of(SubjectType.PUBLIC), buildURI(".well-known/jwks.json"));

        providerMetadata.setTokenEndpointURI(buildURI("token"));
        providerMetadata.setUserInfoEndpointURI(buildURI("userinfo"));
        providerMetadata.setAuthorizationEndpointURI(buildURI("authorize"));
        providerMetadata.setRegistrationEndpointURI(buildURI("connect/register"));
        providerMetadata.setTokenEndpointAuthMethods(List.of(ClientAuthenticationMethod.CLIENT_SECRET_POST));
        providerMetadata.setScopes(new Scope("openid", "profile", "email"));
        providerMetadata.setResponseTypes(List.of(new ResponseType("code")));
        providerMetadata.setGrantTypes(List.of(GrantType.AUTHORIZATION_CODE));
        providerMetadata.setClaimTypes(List.of(ClaimType.NORMAL));
        providerMetadata.setClaims(List.of("sub", "gender", "family_name", "given_name", "email"));
        providerMetadata.setIDTokenJWSAlgs(List.of(JWSAlgorithm.RS256));

        return providerMetadata.toString();
    }

    private URI buildURI(String prefix) throws URISyntaxException {
        return new URI(this.configuration.getBaseUrl().toString() + prefix);
    }


    @GET
    @Path("/jwks.json")
    @Produces("application/json")
    public Response jwks() {
        JWKSet jwkSet = new JWKSet(tokenService.getSigningKey());

        return Response.ok(jwkSet.toJSONObject(true)).build();
    }
}
