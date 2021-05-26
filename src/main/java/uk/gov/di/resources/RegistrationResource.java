package uk.gov.di.resources;

import org.eclipse.jetty.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.PasswordValidation;

import javax.validation.constraints.NotNull;
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

@Path("/registration")
public class RegistrationResource {

    private AuthenticationService authenticationService;
    private ValidationService validationService;

    public RegistrationResource(AuthenticationService authenticationService, ValidationService validationService) {
        this.authenticationService = authenticationService;
        this.validationService = validationService;
    }

    private static final Logger LOG = LoggerFactory.getLogger(RegistrationResource.class);

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/validate")
    public Response setPassword(
            @FormParam("authRequest") String authRequest,
            @FormParam("email") @NotNull String email,
            @FormParam("password") @NotNull String password,
            @FormParam("password-confirm") @NotNull String passwordConfirm) {
        Set<PasswordValidation> passwordValidationErrors = validationService.validatePassword(password, passwordConfirm);
        if (passwordValidationErrors.isEmpty()) {
            authenticationService.signUp(email, password);
                return Response.ok()
                        .cookie(
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
            return Response.status(HttpStatus.BAD_REQUEST_400).entity(passwordValidationErrors).build();
        }
    }

    @POST
    @Path("/verifyAccessCode")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response verificationCode(
            @FormParam("email") String username, @FormParam("code") String code) {

        LOG.info("/verifyAccessCode: {} {}", username, code);

        if (authenticationService.verifyAccessCode(username, code)) {
            return Response.ok().build();
        } else {
            return Response.status(Response.Status.BAD_REQUEST).entity("code-not-valid").build();
        }
    }
}
