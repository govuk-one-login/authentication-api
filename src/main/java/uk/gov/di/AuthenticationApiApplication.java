package uk.gov.di;

import io.dropwizard.Application;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import uk.gov.di.configuration.AuthenticationApiConfiguration;
import uk.gov.di.resources.AuthorisationResource;

public class AuthenticationApiApplication extends Application<AuthenticationApiConfiguration> {

    public static void main(String[] args) throws Exception {
        new AuthenticationApiApplication().run(args);
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
        env.jersey().register(new AuthorisationResource());
    }
}
