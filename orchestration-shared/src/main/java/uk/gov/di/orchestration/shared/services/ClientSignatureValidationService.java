package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;
import software.amazon.awssdk.services.lambda.model.LambdaException;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.PublicKeySource;
import uk.gov.di.orchestration.shared.entity.RpPublicKeyCache;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.validation.PrivateKeyJwtAuthPublicKeySelector;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collections;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

public class ClientSignatureValidationService {

    private static final Logger LOG = LogManager.getLogger(ClientSignatureValidationService.class);
    private static final String TOKEN_PATH = "token";

    private final OidcAPI oidcAPI;
    private final ConfigurationService configurationService;
    private final RpPublicKeyCacheService rpPublicKeyCacheService;
    private final LambdaClient lambdaClient;
    private final Json objectMapper = SerializationService.getInstance();

    public ClientSignatureValidationService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.rpPublicKeyCacheService = new RpPublicKeyCacheService(configurationService);
        this.lambdaClient =
                LambdaClient.builder()
                        .region(Region.of(configurationService.getAwsRegion()))
                        .build();
        this.oidcAPI = new OidcAPI(configurationService);
    }

    public ClientSignatureValidationService(
            ConfigurationService configurationService,
            RpPublicKeyCacheService rpPublicKeyCacheService,
            LambdaClient lambdaClient) {
        this.configurationService = configurationService;
        this.rpPublicKeyCacheService = rpPublicKeyCacheService;
        this.lambdaClient = lambdaClient;
        this.oidcAPI = new OidcAPI(configurationService);
    }

    public void validate(SignedJWT signedJWT, ClientRegistry client)
            throws ClientSignatureValidationException {
        try {
            PublicKey publicKey;
            if (configurationService.fetchRpPublicKeyFromJwksEnabled()) {
                publicKey = retrievePublicKey(client, signedJWT.getHeader().getKeyID());
            } else {
                publicKey = convertPemToPublicKey(client.getPublicKey());
            }

            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            if (!signedJWT.verify(verifier)) {
                throw new ClientSignatureValidationException("Failed to verify Signed JWT.");
            }
        } catch (ClientSignatureValidationException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException e) {
            LOG.error("Error validating Signed JWT for Client: {}", client.getClientID());
            throw e instanceof ClientSignatureValidationException clientSigValException
                    ? clientSigValException
                    : new ClientSignatureValidationException(e);
        }
    }

    public void validateTokenClientAssertion(PrivateKeyJWT privateKeyJWT, ClientRegistry client)
            throws ClientSignatureValidationException {
        try {
            PublicKey publicKey;
            if (configurationService.fetchRpPublicKeyFromJwksEnabled()) {
                publicKey =
                        retrievePublicKey(
                                client, privateKeyJWT.getClientAssertion().getHeader().getKeyID());
            } else {
                publicKey = convertPemToPublicKey(client.getPublicKey());
            }
            ClientAuthenticationVerifier<?> authenticationVerifier =
                    new ClientAuthenticationVerifier<>(
                            new PrivateKeyJwtAuthPublicKeySelector(publicKey),
                            Collections.singleton(new Audience(getTokenURI().toString())));
            authenticationVerifier.verify(privateKeyJWT, null, null);
        } catch (InvalidClientException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException e) {
            LOG.error(
                    "Error validating Token Client Assertion JWT for Client: {}",
                    client.getClientID());
            throw new ClientSignatureValidationException(e);
        }
    }

    private PublicKey retrievePublicKey(ClientRegistry client, String kid)
            throws NoSuchAlgorithmException,
                    InvalidKeySpecException,
                    ClientSignatureValidationException {
        try {
            if (client.getPublicKeySource().equals(PublicKeySource.STATIC.getValue())) {
                return convertPemToPublicKey(client.getPublicKey());
            }
            if (kid == null) {
                String error = "Key ID is null but is required to fetch JWKS";
                LOG.error(error);
                throw new ClientSignatureValidationException(error);
            }
            String jwksUrl = client.getJwksUrl();
            if (client.getJwksUrl() == null) {
                String error = "Client JWKS URL is null but is required to fetch JWKS";
                LOG.error(error);
                throw new ClientSignatureValidationException(error);
            }
            Optional<RpPublicKeyCache> cache =
                    rpPublicKeyCacheService.getRpPublicKeyCacheData(client.getClientID(), kid);
            if (cache.isPresent()) {
                return JWK.parse(cache.get().getPublicKey()).toRSAKey().toPublicKey();
            }

            InvokeResponse response = invokeFetchJwksFunction(lambdaClient, jwksUrl, kid);
            String unescapedPayload =
                    objectMapper.readValue(response.payload().asUtf8String(), String.class);
            if (unescapedPayload.equals("error")) {
                String error = "Returned error from FetchJwksHandler";
                LOG.error(error);
                throw new ClientSignatureValidationException(error);
            }

            JWK jwk = JWK.parse(unescapedPayload);
            rpPublicKeyCacheService.addRpPublicKeyCacheData(
                    client.getClientID(), jwk.getKeyID(), jwk.toJSONString());
            return jwk.toRSAKey().toPublicKey();
        } catch (ParseException | Json.JsonException e) {
            throw new RuntimeException();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey convertPemToPublicKey(String publicKeyPem)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedKey = Base64.getMimeDecoder().decode(publicKeyPem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory kf = KeyFactory.getInstance(KeyType.RSA.getValue());
        return kf.generatePublic(keySpec);
    }

    private InvokeResponse invokeFetchJwksFunction(
            LambdaClient awsLambda, String jwksUrl, String kid) {
        try {
            JSONObject jsonObj = new JSONObject();
            jsonObj.put("url", jwksUrl);
            jsonObj.put("keyId", kid);
            String json = jsonObj.toString();
            SdkBytes payload = SdkBytes.fromUtf8String(json);

            InvokeRequest request =
                    InvokeRequest.builder()
                            .functionName(
                                    configurationService.getEnvironment() + "-FetchJwksFunction")
                            .payload(payload)
                            .build();
            return awsLambda.invoke(request);
        } catch (LambdaException e) {
            throw new RuntimeException();
        }
    }

    private URI getTokenURI() {
        return buildURI(oidcAPI.baseURI(), TOKEN_PATH);
    }
}
