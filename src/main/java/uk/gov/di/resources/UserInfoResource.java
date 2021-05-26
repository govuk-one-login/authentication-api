package uk.gov.di.resources;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.eclipse.jetty.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.TokenService;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/userinfo")
public class UserInfoResource {

    private static final Logger LOG = LoggerFactory.getLogger(UserInfoResource.class);

    private final TokenService tokenService;
    private final AuthenticationService authenticationService;

    public UserInfoResource(
            TokenService tokenService, AuthenticationService authenticationService) {
        this.tokenService = tokenService;
        this.authenticationService = authenticationService;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response userinfo(@HeaderParam("Authorization") String authorizationHeader) {

        try {
            AccessToken accessToken = AccessToken.parse(authorizationHeader);

            var email = tokenService.getEmailForToken(accessToken);
            LOG.info("UserInfoResource.userinfo: {} {}", email, accessToken.toJSONString());
            var userInfo = authenticationService.getInfoForEmail(email);

            return Response.ok(userInfo.toJSONObject()).build();
        } catch (ParseException e) {
            LOG.info("UserInfoResource.userinfo ParseException {}", e);
            return Response.status(HttpStatus.UNAUTHORIZED_401).build();
        }
    }
}
