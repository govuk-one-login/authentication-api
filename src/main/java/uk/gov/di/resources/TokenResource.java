package uk.gov.di.resources;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.eclipse.jetty.http.HttpStatus;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AuthorizationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.TokenService;

import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/token")
public class TokenResource {

    private final TokenService tokenService;
    private final ClientService clientService;
    private final AuthenticationService authenticationService;
    private final AuthorizationCodeService authorizationCodeService;

    public TokenResource(
            TokenService tokenService,
            ClientService clientService,
            AuthenticationService authenticationService, AuthorizationCodeService authorizationCodeService) {
        this.tokenService = tokenService;
        this.clientService = clientService;
        this.authenticationService = authenticationService;
        this.authorizationCodeService = authorizationCodeService;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTokens(
            @FormParam("code") @NotNull AuthorizationCode code,
            @FormParam("client_id") @NotNull String clientId,
            @FormParam("client_secret") @NotNull String clientSecret)
            throws ParseException {

        if (!clientService.isValidClient(clientId, clientSecret)) {
            throw new RuntimeException("Bad authentication request");
        }

        var email = authorizationCodeService.getEmailForCode(code);

        if (email.isEmpty()) {
            return Response.status(HttpStatus.FORBIDDEN_403).build();
        }

        AccessToken accessToken = tokenService.issueToken(email.get());
        UserInfo userInfo = authenticationService.getInfoForEmail(email.get());
        SignedJWT idToken = tokenService.generateIDToken(clientId, userInfo.getSubject());

        OIDCTokens oidcTokens = new OIDCTokens(idToken, accessToken, null);
        OIDCTokenResponse tokenResponse = new OIDCTokenResponse(oidcTokens);

        return Response.ok(tokenResponse.toJSONObject()).build();
    }
}
