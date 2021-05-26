package uk.gov.di;

import io.dropwizard.Application;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.glassfish.jersey.server.ServerProperties;
import uk.gov.di.configuration.AuthenticationApiConfiguration;
import uk.gov.di.entity.Client;
import uk.gov.di.resources.AuthorisationResource;
import uk.gov.di.resources.ClientRegistrationResource;
import uk.gov.di.resources.LoginResource;
import uk.gov.di.resources.LogoutResource;
import uk.gov.di.resources.RegistrationResource;
import uk.gov.di.resources.TokenResource;
import uk.gov.di.resources.UserInfoResource;
import uk.gov.di.resources.WellKnownResource;
import uk.gov.di.services.AuthorizationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.TokenService;
import uk.gov.di.services.UserService;
import uk.gov.di.services.ValidationService;

import java.util.List;

public class AuthenticationApiApplication extends Application<AuthenticationApiConfiguration> {

    public static void main(String[] args) throws Exception {
        new AuthenticationApiApplication().run(args);
    }

    @Override
    public String getName() {
        return "oidc-provider-api";
    }

    @Override
    public void initialize(Bootstrap<AuthenticationApiConfiguration> bootstrap) {
        bootstrap.setConfigurationSourceProvider(
                new SubstitutingSourceProvider(
                        bootstrap.getConfigurationSourceProvider(),
                        new EnvironmentVariableSubstitutor(false)));
    }

    @Override
    public void run(AuthenticationApiConfiguration configuration, Environment env) throws Exception {
        List<Client> clients = List.of(
                new Client(
                        "client-name",
                        "test-id",
                        "test-secret",
                        List.of("email"),
                        List.of("code"),
                        List.of("http://localhost:8080"),
                        List.of("contact@example.com")));


        var authorizationCodeService = new AuthorizationCodeService();
        var clientService =
                new ClientService(clients, new AuthorizationCodeService());
        var authenticationService = new UserService();
        var tokenService = new TokenService(configuration);
        var validationService = new ValidationService();

        env.jersey().register(new AuthorisationResource(clientService));
        env.jersey().register(new LoginResource(authenticationService, clientService, validationService));
        env.jersey().register(new RegistrationResource(authenticationService, validationService));
        env.jersey().register(new UserInfoResource(tokenService, authenticationService));
        env.jersey()
                .register(new TokenResource(tokenService, clientService, authenticationService, authorizationCodeService));
        env.jersey().register(new LogoutResource());
        env.jersey().register(new WellKnownResource(tokenService, configuration));
        env.jersey().register(new ClientRegistrationResource(clientService, configuration));
        env.jersey()
                .property(ServerProperties.LOCATION_HEADER_RELATIVE_URI_RESOLUTION_DISABLED, true);
    }
}
