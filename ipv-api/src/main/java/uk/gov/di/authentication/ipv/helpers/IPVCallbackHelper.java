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
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.IdentityClaims;
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
import uk.gov.di.orchestration.shared.services.AuthorisationCodeService;
import uk.gov.di.orchestration.shared.services.AwsSqsClient;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class IPVCallbackHelper {
    private static final Logger LOG = LogManager.getLogger(IPVCallbackHelper.class);
    protected final Json objectMapper;
    private final AuditService auditService;
    private final AuthCodeResponseGenerationService authCodeResponseService;
    private final AuthorisationCodeService authorisationCodeService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final ConfigurationService configurationService;
    private final DynamoClientService dynamoClientService;
    private final DynamoIdentityService dynamoIdentityService;
    private final DynamoService dynamoService;
    private final SessionService sessionService;
    private final AwsSqsClient sqsClient;

    public IPVCallbackHelper(ConfigurationService configurationService) {
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.authorisationCodeService = new AuthorisationCodeService(configurationService);
        this.configurationService = configurationService;
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.dynamoIdentityService = new DynamoIdentityService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.objectMapper = SerializationService.getInstance();
        this.sessionService = new SessionService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getSpotQueueURI().toString(),
                        configurationService.getSqsEndpointURI().map(URI::toString));
        this.authCodeResponseService =
                new AuthCodeResponseGenerationService(configurationService, dynamoService);
    }

    public IPVCallbackHelper(
            AuditService auditService,
            AuthCodeResponseGenerationService authCodeResponseService,
            AuthorisationCodeService authorisationCodeService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            DynamoClientService dynamoClientService,
            DynamoIdentityService dynamoIdentityService,
            DynamoService dynamoService,
            SerializationService objectMapper,
            SessionService sessionService,
            AwsSqsClient sqsClient) {
        this.auditService = auditService;
        this.authCodeResponseService = authCodeResponseService;
        this.authorisationCodeService = authorisationCodeService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
        this.dynamoClientService = dynamoClientService;
        this.dynamoIdentityService = dynamoIdentityService;
        this.dynamoService = dynamoService;
        this.objectMapper = objectMapper;
        this.sessionService = sessionService;
        this.sqsClient = sqsClient;
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
                var trustmarkURL =
                        configurationService
                                .getOidcApiBaseURL()
                                .map(uri -> buildURI(uri, "trustmark"))
                                .orElseThrow()
                                .toString();
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
            ClientSession clientSession,
            Subject rpPairwiseSubject,
            String internalPairwiseSubjectId,
            UserInfo userIdentityUserInfo,
            String ipAddress,
            String persistentSessionId)
            throws UserNotFoundException {
        LOG.warn("SPOT will not be invoked due to returnCode. Returning authCode to RP");
        segmentedFunctionCall(
                "saveIdentityClaims",
                () -> saveIdentityClaimsToDynamo(rpPairwiseSubject, userIdentityUserInfo));
        var authCode =
                authorisationCodeService.generateAndSaveAuthorisationCode(
                        clientSessionId, userProfile.getEmail(), clientSession);
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
                        session, clientSession, clientSessionId, false, false);

        var subjectId = authCodeResponseService.getSubjectId(session);
        auditService.submitAuditEvent(
                IPVAuditableEvent.AUTH_CODE_ISSUED,
                authRequest.getClientID().getValue(),
                TxmaAuditUser.user()
                        .withGovukSigninJourneyId(clientSessionId)
                        .withSessionId(session.getSessionId())
                        .withUserId(internalPairwiseSubjectId)
                        .withEmail(
                                Optional.ofNullable(session.getEmailAddress())
                                        .orElse(AuditService.UNKNOWN))
                        .withIpAddress(ipAddress)
                        .withPersistentSessionId(persistentSessionId),
                pair("internalSubjectId", subjectId),
                pair("isNewAccount", session.isNewAccount()),
                pair("rpPairwiseId", rpPairwiseSubject.getValue()),
                pair("nonce", authRequest.getNonce()),
                pair("authCode", authCode));

        var isTestJourney =
                dynamoClientService.isTestJourney(clientSessionId, session.getEmailAddress());
        LOG.info("Is journey a test journey: {}", isTestJourney);

        cloudwatchMetricsService.incrementCounter("SignIn", dimensions);
        cloudwatchMetricsService.incrementSignInByClient(
                session.isNewAccount(),
                clientSessionId,
                clientSession.getClientName(),
                isTestJourney);

        authCodeResponseService.saveSession(false, sessionService, session);

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
                        .withVtm(
                                configurationService
                                        .getOidcApiBaseURL()
                                        .map(uri -> buildURI(uri, "trustmark"))
                                        .orElseThrow()
                                        .toString());

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
            Subject rpPairwiseSubject, UserInfo userIdentityUserInfo) {
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
                rpPairwiseSubject.getValue(),
                additionalClaims,
                (String) userIdentityUserInfo.getClaim(VOT.getValue()),
                ipvCoreIdentityString);
    }
}
