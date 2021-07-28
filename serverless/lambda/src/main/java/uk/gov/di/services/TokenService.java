package uk.gov.di.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import uk.gov.di.helpers.TokenGenerator;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class TokenService {

    private final RSAKey signingKey;

    private final Map<AccessToken, String> tokensMap = new HashMap<>();
    private final ConfigurationService configService;
    private final RedisConnectionService redisConnectionService;

    public TokenService(
            ConfigurationService configService, RedisConnectionService redisConnectionService) {
        this.configService = configService;
        this.redisConnectionService = redisConnectionService;
        try {
            signingKey = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public SignedJWT generateIDToken(String clientId, Subject subject) {
        return TokenGenerator.generateIDToken(
                clientId, subject, configService.getBaseURL().get(), signingKey);
    }

    public AccessToken generateAndStoreAccessToken(
            String clientId, Subject subject, List<String> scopes) {
        SignedJWT signedJWT =
                TokenGenerator.generateAccessToken(
                        clientId, configService.getBaseURL().get(), scopes, signingKey);
        AccessToken accessToken = new BearerAccessToken(signedJWT.serialize());

        redisConnectionService.saveWithExpiry(
                accessToken.toJSONString(),
                subject.toString(),
                configService.getAccessTokenExpiry());
        return accessToken;
    }

    public Optional<String> getSubjectWithAccessToken(AccessToken token) {
        return Optional.ofNullable(redisConnectionService.getValue(token.toJSONString()));
    }

    public JWK getSigningKey() {
        return signingKey;
    }

    public boolean validatePrivateKeyJWTSignature(
            String publicKey, PrivateKeyJWT privateKeyJWT, String baseUrl) {
        ClientAuthenticationVerifier<?> authenticationVerifier =
                new ClientAuthenticationVerifier<>(
                        generateClientCredentialsSelector(publicKey),
                        Collections.singleton(new Audience(baseUrl)));
        try {
            authenticationVerifier.verify(privateKeyJWT, null, null);
        } catch (InvalidClientException | JOSEException e) {
            return false;
        }
        return true;
    }

    private ClientCredentialsSelector<?> generateClientCredentialsSelector(String publicKey) {
        return new ClientCredentialsSelector<>() {
            @Override
            public List<Secret> selectClientSecrets(
                    ClientID claimedClientID,
                    ClientAuthenticationMethod authMethod,
                    com.nimbusds.oauth2.sdk.auth.verifier.Context context) {
                return null;
            }

            @Override
            public List<PublicKey> selectPublicKeys(
                    ClientID claimedClientID,
                    ClientAuthenticationMethod authMethod,
                    JWSHeader jwsHeader,
                    boolean forceRefresh,
                    com.nimbusds.oauth2.sdk.auth.verifier.Context context) {

                byte[] decodedKey = Base64.getMimeDecoder().decode(publicKey);
                try {
                    X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(decodedKey);
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    return Collections.singletonList(kf.generatePublic(x509publicKey));
                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }
}
