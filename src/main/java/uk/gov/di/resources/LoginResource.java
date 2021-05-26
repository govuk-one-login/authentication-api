package uk.gov.di.resources;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.eclipse.jetty.http.HttpStatus;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.EmailValidation;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.util.Set;

@Path("/login")
public class LoginResource {

    private final AuthenticationService authenticationService;
    private final ClientService clientService;
    private final ValidationService validationService;

    public LoginResource(AuthenticationService authenticationService, ClientService clientService, ValidationService validationService) {
        this.authenticationService = authenticationService;
        this.clientService = clientService;
        this.validationService = validationService;
    }


    @POST
    public Response login(
            @FormParam("authRequest") String authRequest, @FormParam("email") String email) {
        Set<EmailValidation> emailErrors = validationService.validateEmailAddress(email);
        if (!emailErrors.isEmpty()) {
            return Response.status(HttpStatus.BAD_REQUEST_400).entity(emailErrors).build();
        }
        if (authenticationService.userExists(email)) {
            return Response.ok().entity("user-exists").build();
        } else {
            return Response.status(HttpStatus.NOT_FOUND_404).entity("user-does-not-exist").build();
        }
    }

    @POST
    @Path("/validate")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response validateLogin(
            @FormParam("authRequest") String authRequest,
            @FormParam("email") String email,
            @FormParam("password") String password) throws ParseException {
        boolean isValid = authenticationService.login(email, password);
        if (isValid) {
            AuthenticationRequest request = AuthenticationRequest.parse(authRequest);
            String clientName = clientService.getClient(request.getClientID().getValue()).get().clientName();
            return Response.ok().cookie(
                            new NewCookie(
                                    "userCookie",
                                    email,
                                    "/",
                                    null,
                                    Cookie.DEFAULT_VERSION,
                                    null,
                                    NewCookie.DEFAULT_MAX_AGE,
                                    false))
                    .build();
        } else {
            return Response.status(HttpStatus.BAD_REQUEST_400).entity("authentication-failed").build();
        }
    }
}
