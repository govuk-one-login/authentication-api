package uk.gov.di.authentication.ipv.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IpvCallbackException;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.authentication.ipv.entity.SPOTClaims;
import uk.gov.di.authentication.ipv.entity.SPOTRequest;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.IdentityClaims;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.UserNotFoundException;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthCodeResponseGenerationService;
import uk.gov.di.orchestration.shared.services.AwsSqsClient;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class IPVCallbackHelper {
    private static final Logger LOG = LogManager.getLogger(IPVCallbackHelper.class);
    protected final Json objectMapper;
    private final AuditService auditService;
    private final AuthCodeResponseGenerationService authCodeResponseService;
    private final OrchAuthCodeService orchAuthCodeService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final DynamoClientService dynamoClientService;
    private final DynamoIdentityService dynamoIdentityService;
    private final DynamoService dynamoService;
    private final SessionService sessionService;
    private final AwsSqsClient sqsClient;
    private final OidcAPI oidcAPI;
    private final OrchSessionService orchSessionService;

    public IPVCallbackHelper(ConfigurationService configurationService) {
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.orchAuthCodeService = new OrchAuthCodeService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.dynamoIdentityService = new DynamoIdentityService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.objectMapper = SerializationService.getInstance();
        this.sessionService = new SessionService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getSpotQueueURI(),
                        configurationService.getSqsEndpointURI());
        this.authCodeResponseService =
                new AuthCodeResponseGenerationService(configurationService, dynamoService);
        this.oidcAPI = new OidcAPI(configurationService);
        this.orchSessionService = new OrchSessionService(configurationService);
    }

    public IPVCallbackHelper(
            ConfigurationService configurationService, RedisConnectionService redis) {
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.orchAuthCodeService = new OrchAuthCodeService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.dynamoIdentityService = new DynamoIdentityService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.objectMapper = SerializationService.getInstance();
        this.sessionService = new SessionService(configurationService, redis);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getSpotQueueURI(),
                        configurationService.getSqsEndpointURI());
        this.authCodeResponseService =
                new AuthCodeResponseGenerationService(configurationService, dynamoService);
        this.oidcAPI = new OidcAPI(configurationService);
        this.orchSessionService = new OrchSessionService(configurationService);
    }

    public IPVCallbackHelper(
            AuditService auditService,
            AuthCodeResponseGenerationService authCodeResponseService,
            OrchAuthCodeService orchAuthCodeService,
            CloudwatchMetricsService cloudwatchMetricsService,
            DynamoClientService dynamoClientService,
            DynamoIdentityService dynamoIdentityService,
            DynamoService dynamoService,
            SerializationService objectMapper,
            SessionService sessionService,
            AwsSqsClient sqsClient,
            OidcAPI oidcApi,
            OrchSessionService orchSessionService) {
        this.auditService = auditService;
        this.authCodeResponseService = authCodeResponseService;
        this.orchAuthCodeService = orchAuthCodeService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.dynamoClientService = dynamoClientService;
        this.dynamoIdentityService = dynamoIdentityService;
        this.dynamoService = dynamoService;
        this.objectMapper = objectMapper;
        this.sessionService = sessionService;
        this.sqsClient = sqsClient;
        this.oidcAPI = oidcApi;
        this.orchSessionService = orchSessionService;
    }

    public APIGatewayProxyResponseEvent generateAuthenticationErrorResponse(
            AuthenticationRequest authenticationRequest,
            ErrorObject errorObject,
            boolean noSessionErrorResponse,
            String clientSessionId,
            String sessionId) {
        LOG.warn(
                "Error in IPV AuthorisationResponse. ErrorCode: {}. ErrorDescription: {}. No Session Error: {}",
                errorObject.getCode(),
                errorObject.getDescription(),
                noSessionErrorResponse);
        auditService.submitAuditEvent(
                IPVAuditableEvent.IPV_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                authenticationRequest.getClientID().getValue(),
                TxmaAuditUser.user()
                        .withGovukSigninJourneyId(clientSessionId)
                        .withSessionId(sessionId));
        var errorResponse =
                new AuthenticationErrorResponse(
                        authenticationRequest.getRedirectionURI(),
                        errorObject,
                        authenticationRequest.getState(),
                        authenticationRequest.getResponseMode());
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, errorResponse.toURI().toString()), null);
    }

    public Optional<ErrorObject> validateUserIdentityResponse(
            UserInfo userIdentityUserInfo, List<VectorOfTrust> vtrList)
            throws IpvCallbackException {
        LOG.info("Validating userinfo response");
        for (VectorOfTrust vtr : vtrList) {
            if (vtr.getLevelOfConfidence()
                    .getValue()
                    .equals(userIdentityUserInfo.getClaim(VOT.getValue()))) {
                var trustmarkURL = oidcAPI.trustmarkURI().toString();

                if (!trustmarkURL.equals(userIdentityUserInfo.getClaim(VTM.getValue()))) {
                    LOG.warn("VTM does not contain expected trustmark URL");
                    throw new IpvCallbackException("IPV trustmark is invalid");
                }
                return Optional.empty();
            }
        }
        LOG.warn("IPV missing vot or vot not in vtr list.");
        return Optional.of(OAuth2Error.ACCESS_DENIED);
    }

    public AuthenticationSuccessResponse generateReturnCodeAuthenticationResponse(
            AuthenticationRequest authRequest,
            String clientSessionId,
            UserProfile userProfile,
            Session session,
            String sessionId,
            OrchSessionItem orchSession,
            String clientName,
            Subject rpPairwiseSubject,
            String internalPairwiseSubjectId,
            UserInfo userIdentityUserInfo,
            String ipAddress,
            String persistentSessionId,
            String clientId)
            throws UserNotFoundException {
        LOG.warn("SPOT will not be invoked due to returnCode. Returning authCode to RP");
        segmentedFunctionCall(
                "saveIdentityClaims",
                () ->
                        saveIdentityClaimsToDynamo(
                                clientSessionId, rpPairwiseSubject, userIdentityUserInfo));

        var authCode =
                orchAuthCodeService.generateAndSaveAuthorisationCode(
                        clientId,
                        clientSessionId,
                        userProfile.getEmail(),
                        orchSession.getAuthTime());

        var authenticationResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        authRequest.getResponseMode());

        var dimensions =
                authCodeResponseService.getDimensions(
                        orchSession, clientName, clientSessionId, false, false);

        var subjectId = authCodeResponseService.getSubjectId(session);

        var metadataPairs = new ArrayList<AuditService.MetadataPair>();
        metadataPairs.add(pair("internalSubjectId", subjectId));
        metadataPairs.add(pair("isNewAccount", orchSession.getIsNewAccount()));
        metadataPairs.add(pair("rpPairwiseId", rpPairwiseSubject.getValue()));
        metadataPairs.add(pair("authCode", authCode));
        if (authRequest.getNonce() != null) {
            metadataPairs.add(pair("nonce", authRequest.getNonce().getValue()));
        }

        auditService.submitAuditEvent(
                IPVAuditableEvent.AUTH_CODE_ISSUED,
                authRequest.getClientID().getValue(),
                TxmaAuditUser.user()
                        .withGovukSigninJourneyId(clientSessionId)
                        .withSessionId(sessionId)
                        .withUserId(internalPairwiseSubjectId)
                        .withEmail(
                                Optional.ofNullable(session.getEmailAddress())
                                        .orElse(AuditService.UNKNOWN))
                        .withIpAddress(ipAddress)
                        .withPersistentSessionId(persistentSessionId),
                metadataPairs.toArray(AuditService.MetadataPair[]::new));

        var isTestJourney =
                dynamoClientService.isTestJourney(clientSessionId, session.getEmailAddress());
        LOG.info("Is journey a test journey: {}", isTestJourney);

        cloudwatchMetricsService.incrementCounter("SignIn", dimensions);

        cloudwatchMetricsService.incrementSignInByClient(
                orchSession.getIsNewAccount(), clientId, clientName, isTestJourney);

        authCodeResponseService.saveSession(
                false, sessionService, session, sessionId, orchSessionService, orchSession);
        return authenticationResponse;
    }

    public void queueSPOTRequest(
            LogIds logIds,
            String sectorIdentifier,
            UserProfile userProfile,
            Subject pairwiseSubject,
            UserInfo userIdentityUserInfo,
            String clientId)
            throws JsonException {
        LOG.info("Constructing SPOT request ready to queue");
        var spotClaimsBuilder =
                SPOTClaims.builder()
                        .withClaim(VOT.getValue(), userIdentityUserInfo.getClaim(VOT.getValue()))
                        .withClaim(
                                IdentityClaims.CREDENTIAL_JWT.getValue(),
                                userIdentityUserInfo
                                        .toJSONObject()
                                        .get(IdentityClaims.CREDENTIAL_JWT.getValue()))
                        .withClaim(
                                IdentityClaims.CORE_IDENTITY.getValue(),
                                userIdentityUserInfo
                                        .toJSONObject()
                                        .get(IdentityClaims.CORE_IDENTITY.getValue()))
                        .withVtm(oidcAPI.trustmarkURI().toString());

        var spotRequest =
                new SPOTRequest(
                        spotClaimsBuilder.build(),
                        userProfile.getSubjectID(),
                        dynamoService.getOrGenerateSalt(userProfile),
                        sectorIdentifier,
                        pairwiseSubject.getValue(),
                        logIds,
                        clientId);
        var spotRequestString = objectMapper.writeValueAsString(spotRequest);
        sqsClient.send(spotRequestString);
        LOG.info("SPOT request placed on queue");
    }

    public void saveIdentityClaimsToDynamo(
            String clientSessionId, Subject rpPairwiseSubject, UserInfo userIdentityUserInfo) {
        LOG.info("Checking for additional identity claims to save to dynamo");
        var additionalClaims = new HashMap<String, String>();
        ValidClaims.getAllValidClaims().stream()
                .filter(t -> !t.equals(ValidClaims.CORE_IDENTITY_JWT.getValue()))
                .filter(claim -> Objects.nonNull(userIdentityUserInfo.toJSONObject().get(claim)))
                .forEach(
                        finalClaim ->
                                additionalClaims.put(
                                        finalClaim,
                                        userIdentityUserInfo
                                                .toJSONObject()
                                                .get(finalClaim)
                                                .toString()));
        LOG.info("Additional identity claims present: {}", !additionalClaims.isEmpty());

        var ipvCoreIdentityClaim =
                userIdentityUserInfo.getClaim(IdentityClaims.CORE_IDENTITY.getValue());
        String ipvCoreIdentityString =
                ipvCoreIdentityClaim == null ? "" : ipvCoreIdentityClaim.toString();
        dynamoIdentityService.saveIdentityClaims(
                clientSessionId,
                rpPairwiseSubject.getValue(),
                additionalClaims,
                (String) userIdentityUserInfo.getClaim(VOT.getValue()),
                ipvCoreIdentityString);
    }
}
