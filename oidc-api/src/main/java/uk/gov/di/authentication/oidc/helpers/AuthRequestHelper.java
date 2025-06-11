package uk.gov.di.authentication.oidc.helpers;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

public class AuthRequestHelper {
    private AuthRequestHelper() {}

    /* Custom parameters on the auth request are a bit weird. They can be null, or they can be a list of strings,
     * even if you only add 1 custom parameter.
     * In a lot of places we check if its null then call authRequest.getCustomParameter(x).get(0)
     * This is a helper method to get the first string in that list of strings as an optional.
     */
    public static Optional<String> getCustomParameterOpt(
            AuthenticationRequest authRequest, String parameter) {
        return Optional.ofNullable(authRequest.getCustomParameter(parameter))
                .map(List::stream)
                .flatMap(Stream::findFirst);
    }
}
