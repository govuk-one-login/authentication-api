package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.nimbusds.oauth2.sdk.id.Subject;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@DynamoDbBean
public class ClientSession {

    private String clientSessionId;

    @Expose private Map<String, List<String>> authRequestParams;

    @Expose private String idTokenHint;

    @Expose private LocalDateTime creationDate;

    /**
     * @deprecated ClientSession is to use vtrList and no longer use effectiveVectorOfTrust. Must be
     *     retained until Authentication no longer depend on this field.
     */
    @Deprecated(forRemoval = true)
    @Expose
    private VectorOfTrust effectiveVectorOfTrust;

    @Expose private List<VectorOfTrust> vtrList;

    @Expose private String rpPairwiseId;

    @Expose private Subject docAppSubjectId;

    @Expose private String clientName;

    public ClientSession() {}

    public ClientSession(
            Map<String, List<String>> authRequestParams,
            LocalDateTime creationDate,
            List<VectorOfTrust> vtrList,
            String clientName) {
        this.authRequestParams = authRequestParams;
        this.creationDate = creationDate;
        this.vtrList = vtrList;
        if (!vtrList.isEmpty()) {
            this.effectiveVectorOfTrust = VectorOfTrust.orderVtrList(vtrList).get(0);
        }
        this.clientName = clientName;
    }

    public ClientSession setIdTokenHint(String idTokenHint) {
        this.idTokenHint = idTokenHint;
        return this;
    }

    @DynamoDbPartitionKey
    @DynamoDbAttribute("ClientSessionId")
    public String getClientSessionId() {
        return clientSessionId;
    }

    public void setClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
    }

    public ClientSession withClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
        return this;
    }

    @DynamoDbAttribute("AuthRequestParams")
    public Map<String, List<String>> getAuthRequestParams() {
        return authRequestParams;
    }

    @DynamoDbAttribute("IdTokenHint")
    public String getIdTokenHint() {
        return idTokenHint;
    }

    @DynamoDbAttribute("CreationDate")
    public LocalDateTime getCreationDate() {
        return creationDate;
    }

    @DynamoDbAttribute("VtrList")
    public List<VectorOfTrust> getVtrList() {
        return vtrList;
    }

    @DynamoDbAttribute("RpPairwiseId")
    public String getRpPairwiseId() {
        return rpPairwiseId;
    }

    public ClientSession setRpPairwiseId(String rpPairwiseId) {
        this.rpPairwiseId = rpPairwiseId;
        return this;
    }

    @DynamoDbAttribute("DocAppSubjectId")
    public Subject getDocAppSubjectId() {
        return docAppSubjectId;
    }

    public ClientSession setDocAppSubjectId(Subject docAppSubjectId) {
        this.docAppSubjectId = docAppSubjectId;
        return this;
    }

    @DynamoDbAttribute("ClientName")
    public String getClientName() {
        return clientName;
    }

    public String getVtrLocsAsCommaSeparatedString() {
        List<VectorOfTrust> orderedVtrList = VectorOfTrust.orderVtrList(this.vtrList);
        StringBuilder strBuilder = new StringBuilder();
        for (VectorOfTrust vtr : orderedVtrList) {
            String loc =
                    vtr.containsLevelOfConfidence()
                            ? vtr.getLevelOfConfidence().getValue()
                            : LevelOfConfidence.NONE.getValue();
            strBuilder.append(loc).append(",");
        }
        if (!strBuilder.isEmpty()) {
            strBuilder.setLength(strBuilder.length() - 1);
            return strBuilder.toString();
        }
        return "";
    }
}
