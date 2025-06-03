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
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
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
import uk.gov.di.orchestration.shared.exceptions.JwksException;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.validation.PrivateKeyJwtAuthPublicKeySelector;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

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
                        .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                        .build();
        this.oidcAPI = new OidcAPI(configurationService);
    }

    public ClientSignatureValidationService(
            ConfigurationService configurationService,
            RpPublicKeyCacheService rpPublicKeyCacheService,
            LambdaClient lambdaClient,
            OidcAPI oidcAPI) {
        this.configurationService = configurationService;
        this.rpPublicKeyCacheService = rpPublicKeyCacheService;
        this.lambdaClient = lambdaClient;
        this.oidcAPI = oidcAPI;
    }

    public void validate(SignedJWT signedJWT, ClientRegistry client)
            throws ClientSignatureValidationException, JwksException {
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
            throws ClientSignatureValidationException, JwksException {
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
                            Set.of(
                                    new Audience(oidcAPI.tokenURI().toString()),
                                    new Audience(oidcAPI.getIssuerURI().toString())));
            authenticationVerifier.verify(privateKeyJWT, null, null);
        } catch (InvalidClientException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException e) {
            LOG.error(
                    "Error validating Token Client Assertion JWT for Client: {}. Error: {}",
                    client.getClientID(),
                    e.getMessage());
            throw new ClientSignatureValidationException(e);
        }
    }

    private PublicKey retrievePublicKey(ClientRegistry client, String kid)
            throws NoSuchAlgorithmException,
                    InvalidKeySpecException,
                    JwksException,
                    ClientSignatureValidationException {
        try {
            String clientId = client.getClientID();
            if (client.getPublicKeySource().equals(PublicKeySource.STATIC.getValue())) {
                String publicKey = client.getPublicKey();
                if (publicKey == null) {
                    throw new ClientSignatureValidationException(
                            "PublicKey is null but is required when PublicKeySource is static");
                }
                LOG.info("Returning static RP public signing key");
                return convertPemToPublicKey(publicKey);
            }
            if (kid == null) {
                String error =
                        "Key ID is null but is required to fetch key when PublicKeySource is JWKS";
                LOG.error(error);
                throw new JwksException(error);
            }
            String jwksUrl = client.getJwksUrl();
            if (jwksUrl == null) {
                String error =
                        "Client JWKS URL is null but is required to fetch key when PublicKeySource is JWKS";
                LOG.error(error);
                throw new JwksException(error);
            }
            Optional<RpPublicKeyCache> cache =
                    rpPublicKeyCacheService.getRpPublicKeyCacheData(clientId, kid);
            if (cache.isPresent()) {
                LOG.info("Returning cached RP public signing key with key ID {}", kid);
                return JWK.parse(cache.get().getPublicKey()).toRSAKey().toPublicKey();
            }
            LOG.info("Fetching JWKS with key ID {} from {}", kid, jwksUrl);
            InvokeResponse response = invokeFetchJwksFunction(lambdaClient, jwksUrl, kid);
            String unescapedPayload =
                    objectMapper.readValue(response.payload().asUtf8String(), String.class);

            if (unescapedPayload.equals("error")) {
                String error = "Returned error from FetchJwksHandler";
                LOG.error(error);
                throw new JwksException(error);
            }

            JWK jwk = JWK.parse(unescapedPayload);
            LOG.info("Caching RP public signing key with key ID {}", kid);
            rpPublicKeyCacheService.addRpPublicKeyCacheData(
                    clientId, jwk.getKeyID(), jwk.toJSONString());
            return jwk.toRSAKey().toPublicKey();
        } catch (ParseException | Json.JsonException | JOSEException e) {
            String error = "Error parsing JWKS to PublicKey: " + e.getMessage();
            LOG.error(error);
            throw new JwksException(error);
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
            LambdaClient awsLambda, String jwksUrl, String kid) throws JwksException {
        try {
            JSONObject jsonObj = new JSONObject();
            jsonObj.put("url", jwksUrl);
            jsonObj.put("keyId", kid);
            String json = jsonObj.toString();
            SdkBytes payload = SdkBytes.fromUtf8String(json);

            InvokeRequest request =
                    InvokeRequest.builder()
                            .functionName(
                                    configurationService.getEnvironment()
                                            + "-FetchJwksFunction:latest")
                            .payload(payload)
                            .build();
            return awsLambda.invoke(request);
        } catch (LambdaException e) {
            LOG.error("LambdaException thrown while invoking FetchJwksFunction");
            throw new JwksException(e.getMessage());
        }
    }
}
