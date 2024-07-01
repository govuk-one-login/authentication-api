package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;
import software.amazon.awssdk.services.lambda.model.LambdaException;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;

public class RpPublicKeyService {

    private final ClientRegistry clientRegistry;
    private final ConfigurationService configurationService;
    private final Json objectMapper = SerializationService.getInstance();
    private static final Logger LOG = LogManager.getLogger(RpPublicKeyService.class);

    public RpPublicKeyService(
            ClientRegistry clientRegistry, ConfigurationService configurationService) {
        this.clientRegistry = clientRegistry;
        this.configurationService = configurationService;
    }

    public PublicKey retrievePublicKey() {
        boolean fetchPublicKeyFromUrl = true;
        boolean keyIsCached = false;
        try {
            // TODO use the line below once ATO-687 is merged
            // if (clientRegistry.getPublicKeySource() == "jwks_url" ||
            // clientRegistry.getPublicKey() == null) {
            if (fetchPublicKeyFromUrl) {
                if (keyIsCached) {
                    return null;
                } else {
                    String region = Region.of(configurationService.getAwsRegion()).toString();
                    LOG.info("region = " + region);
                    LambdaClient lambdaClient =
                            LambdaClient.builder()
                                    .region(Region.of(configurationService.getAwsRegion()))
                                    .build();
                    String name = configurationService.getEnvironment() + "-FetchJwksFunction";
                    LOG.info("name = " + name);
                    InvokeResponse response =
                            invokeFunction(
                                    lambdaClient,
                                    configurationService.getEnvironment() + "-FetchJwksFunction");
                    String unescapedPayload =
                            objectMapper.readValue(response.payload().asUtf8String(), String.class);
                    LOG.info("unescapedPayload = " + unescapedPayload);
                    if (unescapedPayload.equals("error")) {
                        LOG.error("returned error from FetchJwksHandler");
                        return null;
                    }
                    JWK jwk = JWK.parse(unescapedPayload);
                    return jwk.toECKey().toPublicKey();
                }
            } else {
                return convertToPublicKey(clientRegistry.getPublicKey());
            }
        } catch (ParseException | Json.JsonException e) {
            throw new RuntimeException();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private InvokeResponse invokeFunction(LambdaClient awsLambda, String functionName) {

        // TODO using these test values for now
        var url = "https://oidc.integration.account.gov.uk/.well-known/storage-token-jwk.json";
        var keyId = "a11f7564fcf886515a7d30f8e46865f709478ce7761d6c44927e4b0ea6cca2f4";
        try {
            JSONObject jsonObj = new JSONObject();
            jsonObj.put("url", url);
            jsonObj.put("keyId", keyId);
            String json = jsonObj.toString();
            LOG.info("generating payload");
            SdkBytes payload = SdkBytes.fromUtf8String(json);

            InvokeRequest request =
                    InvokeRequest.builder().functionName(functionName).payload(payload).build();
            return awsLambda.invoke(request);

        } catch (LambdaException e) {
            throw new RuntimeException();
        }
    }

    private static PublicKey convertToPublicKey(String publicKey) {
        try {
            byte[] decodedKey = Base64.getMimeDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOG.error("TODO");
            throw new RuntimeException(e);
        }
    }
}
