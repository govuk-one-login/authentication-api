package uk.gov.di.authentication.oidc.helpers;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.langtag.LangTagUtils;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Objects;

public class RequestObjectToAuthRequestHelper {
    private static final Json objectMapper = SerializationService.getInstance();

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
                transformVtr(builder, jwtClaimsSet);
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("ui_locales"))) {
                try {
                    String uiLocales = (String) jwtClaimsSet.getClaim("ui_locales");
                    if (!uiLocales.isBlank()) {
                        builder.uiLocales(LangTagUtils.parseLangTagList(uiLocales.split(" ")));
                    }
                } catch (ClassCastException e) {
                    LOG.error("Unable to read ui_locales claim: {}", e.getMessage());
                }
            }
            return builder.build();
        } catch (ParseException | com.nimbusds.oauth2.sdk.ParseException | Json.JsonException e) {
            LOG.error("Parse exception thrown whilst converting RequestObject to Auth Request", e);
            throw new RuntimeException(e);
        } catch (Exception e) {
            LOG.error("Unexpected exception thrown", e);
            throw new RuntimeException(e);
        }
    }

    private static void transformVtr(
            AuthenticationRequest.Builder builder, JWTClaimsSet jwtClaimsSet)
            throws Json.JsonException, ParseException {
        var vtrClaim = jwtClaimsSet.getClaim("vtr");
        if (vtrClaim instanceof String vtr) {
            builder.customParameter("vtr", vtr);
        } else if (vtrClaim instanceof List<?> vtrList
                && vtrList.stream().allMatch(vtr -> vtr instanceof String)) {
            builder.customParameter(
                    "vtr",
                    objectMapper.writeValueAsString(jwtClaimsSet.getStringArrayClaim("vtr")));
        }

        LOG.warn("Cannot parse Vectors of Trust");
        throw new RuntimeException("Cannot parse Vectors of Trust");
    }
}
