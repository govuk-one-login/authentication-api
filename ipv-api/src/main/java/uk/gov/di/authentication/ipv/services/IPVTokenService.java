package uk.gov.di.authentication.ipv.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import static java.util.Collections.singletonList;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class IPVTokenService {

    private final ConfigurationService configurationService;
    private static final String TOKEN_PATH = "token";
    public static final String IPV_ACCESS_TOKEN_PREFIX = "IPV_ACCESS_TOKEN:";
    private static final Logger LOG = LogManager.getLogger(IPVTokenService.class);

    public IPVTokenService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public TokenRequest constructTokenRequest(String authCode) {
        var codeGrant =
                new AuthorizationCodeGrant(
                        new AuthorizationCode(authCode),
                        configurationService.getIPVAuthorisationCallbackURI());
        var tokenUri =
                buildURI(configurationService.getIPVAuthorisationURI().toString(), TOKEN_PATH);
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(5);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
        JWTAuthenticationClaimsSet claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(configurationService.getIPVAuthorisationClientId()),
                        new Audience(tokenUri));
        claimsSet.getExpirationTime().setTime(expiryDate.getTime());
        var privateKeyJWT = generatePrivateKeyJwt(claimsSet);
        var extraParams = new HashMap<String, List<String>>();
        extraParams.put(
                "client_id", singletonList(configurationService.getIPVAuthorisationClientId()));
        return new TokenRequest(
                tokenUri,
                privateKeyJWT,
                codeGrant,
                null,
                singletonList(configurationService.getIPVAuthorisationCallbackURI()),
                extraParams);
    }

    public TokenResponse sendTokenRequest(TokenRequest tokenRequest) {
        try {
            return TokenResponse.parse(tokenRequest.toHTTPRequest().send());
        } catch (IOException e) {
            LOG.error("Error whilst sending TokenRequest", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error whilst parsing TokenResponse", e);
            throw new RuntimeException(e);
        }
    }

    private PrivateKeyJWT generatePrivateKeyJwt(JWTAuthenticationClaimsSet claimsSet) {
        KeyPairGenerator kpg;
        PrivateKeyJWT privateKeyJwt;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            var keyPair = kpg.generateKeyPair();
            privateKeyJwt =
                    new PrivateKeyJWT(
                            claimsSet,
                            JWSAlgorithm.RS512,
                            (RSAPrivateKey) keyPair.getPrivate(),
                            null,
                            null);
        } catch (NoSuchAlgorithmException | JOSEException e) {
            LOG.error("Error whilst creating PrivateKeyJWT on the fly");
            throw new RuntimeException(e);
        }
        return privateKeyJwt;
    }
}
