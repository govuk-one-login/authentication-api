package uk.gov.di.resources;

import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import org.eclipse.jetty.http.HttpStatus;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.services.UserService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.PasswordValidation;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(DropwizardExtensionsSupport.class)
class RegistrationResourceTest {

    private static final UserService USER_SERVICE = mock(UserService.class);
    private static final ValidationService VALIDATION_SERVICE = mock(ValidationService.class);

    private static final ResourceExtension REGISTRATION_RESOURCE =
            ResourceExtension.builder()
                    .addResource(new RegistrationResource(USER_SERVICE, VALIDATION_SERVICE))
                    .setClientConfigurator(
                            clientConfig -> {
                                clientConfig.property(ClientProperties.FOLLOW_REDIRECTS, false);
                            })
                    .build();

    @Test
    void shouldReturn200IfPasswordsMatch() {
        Response response =
                setPasswordRequest("newuser@example.com", "reallysecure1234", "reallysecure1234");

        assertEquals(HttpStatus.OK_200, response.getStatus());
        assertEquals("newuser@example.com", response.getCookies().get("userCookie").getValue());
        verify(USER_SERVICE).signUp(eq("newuser@example.com"), eq("reallysecure1234"));
    }

    @Test
    void shouldReturn400IfPasswordsAreInvalid() {
        Set<PasswordValidation> passwordValidationErrors = EnumSet.of(PasswordValidation.PASSWORDS_DO_NOT_MATCH);
        var password = "reallysecure1234";
        var retypedPassword = "notmatchingpassword";

        when(VALIDATION_SERVICE.validatePassword(password, retypedPassword)).thenReturn(passwordValidationErrors);
        Response response = setPasswordRequest("", password, retypedPassword);

        assertEquals(HttpStatus.BAD_REQUEST_400, response.getStatus());
    }

    private Response setPasswordRequest(String email, String password, String passwordConfirm) {
        MultivaluedMap<String, String> setPasswordResourceFormParams = new MultivaluedHashMap<>();
        setPasswordResourceFormParams.add("authRequest", "whatever");
        setPasswordResourceFormParams.add("email", email);
        setPasswordResourceFormParams.add("password", password);
        setPasswordResourceFormParams.add("password-confirm", passwordConfirm);
        return REGISTRATION_RESOURCE
                .target("/registration/validate")
                .request()
                .post(Entity.form(setPasswordResourceFormParams));
    }
}
