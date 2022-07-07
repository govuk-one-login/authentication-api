package uk.gov.di.authentication.oidc.helpers;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.text.ParseException;
import java.util.Objects;

public class RequestObjectToAuthRequestHelper {

    private static final Logger LOG = LogManager.getLogger(RequestObjectToAuthRequestHelper.class);

    private RequestObjectToAuthRequestHelper() {}

    public static AuthenticationRequest transform(AuthenticationRequest authRequest) {
        if (Objects.isNull(authRequest.getRequestObject())) {
            return authRequest;
        }
        try {
            var signedJWT = (SignedJWT) authRequest.getRequestObject();
            var jwtClaimsSet = signedJWT.getJWTClaimsSet();
            var responseType =
                    ResponseType.parse(jwtClaimsSet.getClaim("response_type").toString());
            var builder =
                    new AuthenticationRequest.Builder(
                                    responseType,
                                    Scope.parse(jwtClaimsSet.getClaim("scope").toString()),
                                    new ClientID(jwtClaimsSet.getClaim("client_id").toString()),
                                    URI.create((String) jwtClaimsSet.getClaim("redirect_uri")))
                            .state(new State(jwtClaimsSet.getClaim("state").toString()))
                            .nonce(new Nonce(jwtClaimsSet.getClaim("nonce").toString()))
                            .requestObject(authRequest.getRequestObject());

            if (Objects.nonNull(jwtClaimsSet.getClaim("vtr"))) {
                builder.customParameter("vtr", (String) jwtClaimsSet.getClaim("vtr"));
            }
            return builder.build();
        } catch (ParseException | com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.error("Parse exception thrown whilst converting RequestObject to Auth Request", e);
            throw new RuntimeException(e);
        } catch (Exception e) {
            LOG.error("Unexpected exception thrown", e);
            throw new RuntimeException(e);
        }
    }
}
