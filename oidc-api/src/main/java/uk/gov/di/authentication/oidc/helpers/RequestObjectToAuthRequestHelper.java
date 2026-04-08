package uk.gov.di.authentication.oidc.helpers;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.langtag.LangTagUtils;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import net.minidev.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Objects;

import static com.nimbusds.openid.connect.sdk.Prompt.Type.parse;
import static java.lang.String.format;

public class RequestObjectToAuthRequestHelper {
    private static final Json objectMapper = SerializationService.getInstance();

    private static final Logger LOG = LogManager.getLogger(RequestObjectToAuthRequestHelper.class);

    private RequestObjectToAuthRequestHelper() {}

    @SuppressWarnings("deprecation")
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
                            .requestObject(authRequest.getRequestObject());

            if (Objects.nonNull(jwtClaimsSet.getClaim("claims"))) {
                builder.claims(parseOidcClaims(jwtClaimsSet));
            }

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
            if (Objects.nonNull(jwtClaimsSet.getClaim("rp_sid"))) {
                builder.customParameter("rp_sid", jwtClaimsSet.getClaim("rp_sid").toString());
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("prompt"))) {
                builder.prompt(parse(jwtClaimsSet.getStringClaim("prompt")));
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("id_token_hint"))) {
                builder.customParameter(
                        "id_token_hint", jwtClaimsSet.getStringClaim("id_token_hint"));
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("nonce"))) {
                builder.nonce(Nonce.parse(jwtClaimsSet.getStringClaim("nonce")));
            }

            if (Objects.nonNull(jwtClaimsSet.getClaim("max_age"))) {
                builder.maxAge(getMaxAge(jwtClaimsSet));
            }

            var codeChallenge = jwtClaimsSet.getStringClaim("code_challenge");

            if (Objects.nonNull(codeChallenge)) {
                var parsedCodeChallenge = CodeChallenge.parse(codeChallenge);
                var parsedCodeChallengeMethod =
                        CodeChallengeMethod.parse(
                                jwtClaimsSet.getStringClaim("code_challenge_method"));

                builder.codeChallenge(parsedCodeChallenge, parsedCodeChallengeMethod);
            }

            if (Objects.nonNull(jwtClaimsSet.getStringClaim("_ga"))) {
                builder.customParameter("_ga", jwtClaimsSet.getStringClaim("_ga"));
            }

            if (Objects.nonNull(jwtClaimsSet.getStringClaim("cookie_consent"))) {
                builder.customParameter(
                        "cookie_consent", jwtClaimsSet.getStringClaim("cookie_consent"));
            }

            if (Objects.nonNull(jwtClaimsSet.getClaim("login_hint"))) {
                builder.loginHint(jwtClaimsSet.getStringClaim("login_hint"));
            }

            if (Objects.nonNull(jwtClaimsSet.getStringClaim("channel"))) {
                builder.customParameter("channel", jwtClaimsSet.getStringClaim("channel"));
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
                && vtrList.stream().allMatch(String.class::isInstance)) {
            builder.customParameter(
                    "vtr",
                    objectMapper.writeValueAsString(jwtClaimsSet.getStringArrayClaim("vtr")));
        } else {
            LOG.warn("Cannot parse Vectors of Trust");
            throw new RuntimeException("Cannot parse Vectors of Trust");
        }
    }

    public static OIDCClaimsRequest parseOidcClaims(JWTClaimsSet claimsSet) {
        var stringClaim = claimsSet.getClaim("claims").toString();
        if (stringClaim == null || stringClaim.isEmpty()) {
            throw new IllegalArgumentException("Claims must not be null or empty");
        }

        try {
            return parseClaimsAsJson(claimsSet);
        } catch (java.text.ParseException e) {
            return parseClaimsAsString(claimsSet);
        }
    }

    private static Integer getMaxAge(JWTClaimsSet claimsSet) {
        try {
            return claimsSet.getIntegerClaim("max_age");
        } catch (java.text.ParseException e) {
            return parseStringMaxAge(claimsSet);
        }
    }

    private static Integer parseStringMaxAge(JWTClaimsSet claimsSet) {
        try {
            var stringMaxAge = claimsSet.getStringClaim("max_age");
            return Integer.parseInt(stringMaxAge);
        } catch (java.text.ParseException e) {
            throw new IllegalArgumentException("Max age claim is could not be parsed to integer");
        }
    }

    private static OIDCClaimsRequest parseClaimsAsJson(JWTClaimsSet claimsSet)
            throws ParseException {
        try {
            var claimsObject = claimsSet.getJSONObjectClaim("claims");
            return OIDCClaimsRequest.parse(new JSONObject(claimsObject));
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.warn(format("Failed to parse OIDC claims: %s", e.getMessage()), e);
            throw new RuntimeException("Failed to parse OIDC claims", e);
        }
    }

    private static OIDCClaimsRequest parseClaimsAsString(JWTClaimsSet claimsSet) {
        try {
            var stringClaims = claimsSet.getClaim("claims").toString();
            return OIDCClaimsRequest.parse(stringClaims);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.warn(format("Failed to parse OIDC claims: %s", e.getMessage()), e);
            throw new RuntimeException("Failed to parse OIDC claims", e);
        }
    }
}
