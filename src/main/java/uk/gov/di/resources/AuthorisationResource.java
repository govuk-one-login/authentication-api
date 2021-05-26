package uk.gov.di.resources;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.eclipse.jetty.http.HttpStatus;
import uk.gov.di.helpers.AuthenticationResponseHelper;
import uk.gov.di.services.ClientService;

import javax.ws.rs.CookieParam;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.Optional;

@Path("/authorize")
public class AuthorisationResource {

    private ClientService clientService;

    public AuthorisationResource(ClientService clientService) {
        this.clientService = clientService;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response authorize(
            @Context UriInfo uriInfo, @CookieParam("userCookie") Optional<String> email)
            throws ParseException, RuntimeException {
        var authRequest = AuthenticationRequest.parse(uriInfo.getRequestUri());

        Optional<ErrorObject> error = clientService.getErrorForAuthorizationRequest(authRequest);

        return error
                .map(e -> Response.status(HttpStatus.MOVED_TEMPORARILY_302).location(AuthenticationResponseHelper.generateErrorAuthnResponse(authRequest, e).toURI()).build())
                .orElse(checkIfUserIsLoggedIn(email, authRequest));
    }

    private Response checkIfUserIsLoggedIn(Optional<String> email, AuthenticationRequest authRequest) {
        return email.map(e -> Response.status(HttpStatus.MOVED_TEMPORARILY_302)
                .location(clientService.getSuccessfulResponse(authRequest, e)
                        .toSuccessResponse()
                        .toURI()).build())
                .orElse(Response.status(HttpStatus.MOVED_TEMPORARILY_302)
                        .location(UriBuilder.fromUri(URI.create("/login"))
                                .queryParam("authRequest", authRequest.toQueryString())
                                .build()).build());
    }
}
