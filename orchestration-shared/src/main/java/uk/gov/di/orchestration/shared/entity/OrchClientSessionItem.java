package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.orchestration.shared.converters.VtrListConverter;
import uk.gov.di.orchestration.shared.utils.VtrListUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;

@DynamoDbBean
public class OrchClientSessionItem {
    private static final String ATTRIBUTE_CLIENT_SESSION_ID = "ClientSessionId";
    private static final String ATTRIBUTE_AUTH_REQUEST_PARAMS = "AuthRequestParams";
    private static final String ATTRIBUTE_ID_TOKEN_HINT = "IdTokenHint";
    private static final String ATTRIBUTE_CREATION_DATE = "CreationDate";
    private static final String ATTRIBUTE_VTR_LIST = "VtrList";
    private static final String ATTRIBUTE_RP_PAIRWISE_ID = "RpPairwiseId";
    private static final String ATTRIBUTE_PUBLIC_SUBJECT_ID = "PublicSubjectId";
    private static final String ATTRIBUTE_DOC_APP_SUBJECT_ID = "DocAppSubjectId";
    private static final String ATTRIBUTE_CLIENT_NAME = "ClientName";
    private static final String ATTRIBUTE_TTL = "ttl";
    private String clientSessionId;
    private Map<String, List<String>> authRequestParams;
    private String idTokenHint;
    private LocalDateTime creationDate;
    private List<VectorOfTrust> vtrList;
    private String rpPairwiseId;
    private String publicSubjectId;
    private String docAppSubjectId;
    private String clientName;
    private long timeToLive;

    public OrchClientSessionItem() {}

    public OrchClientSessionItem(String clientSessionId) {
        this.clientSessionId = clientSessionId;
    }

    public OrchClientSessionItem(
            String clientSessionId,
            Map<String, List<String>> authRequestParams,
            LocalDateTime creationDate,
            List<VectorOfTrust> vtrList,
            String clientName) {
        this.clientSessionId = clientSessionId;
        this.authRequestParams = authRequestParams;
        this.creationDate = creationDate;
        this.vtrList = vtrList;
        this.clientName = clientName;
    }

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_CLIENT_SESSION_ID)
    public String getClientSessionId() {
        return clientSessionId;
    }

    public void setClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
    }

    public OrchClientSessionItem withClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_AUTH_REQUEST_PARAMS)
    public Map<String, List<String>> getAuthRequestParams() {
        return authRequestParams;
    }

    public void setAuthRequestParams(Map<String, List<String>> authRequestParams) {
        this.authRequestParams = authRequestParams;
    }

    public OrchClientSessionItem withAuthRequestParams(
            Map<String, List<String>> authRequestParams) {
        this.authRequestParams = authRequestParams;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_ID_TOKEN_HINT)
    public String getIdTokenHint() {
        return idTokenHint;
    }

    public void setIdTokenHint(String idTokenHint) {
        this.idTokenHint = idTokenHint;
    }

    public OrchClientSessionItem withIdTokenHint(String idTokenHint) {
        this.idTokenHint = idTokenHint;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_CREATION_DATE)
    public LocalDateTime getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(LocalDateTime creationDate) {
        this.creationDate = creationDate;
    }

    public OrchClientSessionItem withCreationDate(LocalDateTime creationDate) {
        this.creationDate = creationDate;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_VTR_LIST)
    @DynamoDbConvertedBy(VtrListConverter.class)
    public List<VectorOfTrust> getVtrList() {
        return vtrList;
    }

    public void setVtrList(List<VectorOfTrust> vtrList) {
        this.vtrList = vtrList;
    }

    public OrchClientSessionItem withVtrList(List<VectorOfTrust> vtrList) {
        this.vtrList = vtrList;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_RP_PAIRWISE_ID)
    public String getRpPairwiseId() {
        // This is public because the DynamoDbMapper requires it to be for serialisation.
        // Do not use it directly - use getCorrectPairwiseIdGivenSubjectType instead.
        return rpPairwiseId;
    }

    public void setRpPairwiseId(String rpPairwiseId) {
        this.rpPairwiseId = rpPairwiseId;
    }

    public OrchClientSessionItem withRpPairwiseId(String rpPairwiseId) {
        this.rpPairwiseId = rpPairwiseId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_PUBLIC_SUBJECT_ID)
    public String getPublicSubjectId() {
        // This is public because the DynamoDbMapper requires it to be for serialisation.
        // Do not use it directly - use getCorrectPairwiseIdGivenSubjectType instead.
        return publicSubjectId;
    }

    public void setPublicSubjectId(String publicSubjectId) {
        this.publicSubjectId = publicSubjectId;
    }

    public OrchClientSessionItem withPublicSubjectId(String publicSubjectId) {
        this.publicSubjectId = publicSubjectId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_DOC_APP_SUBJECT_ID)
    public String getDocAppSubjectId() {
        return docAppSubjectId;
    }

    public void setDocAppSubjectId(String docAppSubjectId) {
        this.docAppSubjectId = docAppSubjectId;
    }

    public OrchClientSessionItem withDocAppSubjectId(String docAppSubjectId) {
        this.docAppSubjectId = docAppSubjectId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_CLIENT_NAME)
    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public OrchClientSessionItem withClientName(String clientName) {
        this.clientName = clientName;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TTL)
    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public OrchClientSessionItem withTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
        return this;
    }

    public String getVtrLocsAsCommaSeparatedString() {
        return VtrListUtils.getVtrLocsAsCommaSeparatedString(vtrList);
    }

    public String getCorrectPairwiseIdGivenSubjectType(String subjectType) {
        if (PUBLIC.toString().equalsIgnoreCase(subjectType)) {
            return this.getPublicSubjectId();
        } else {
            return this.getRpPairwiseId();
        }
    }
}
