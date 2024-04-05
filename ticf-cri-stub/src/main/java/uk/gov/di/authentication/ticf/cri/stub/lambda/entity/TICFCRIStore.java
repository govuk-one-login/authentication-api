package uk.gov.di.authentication.ticf.cri.stub.lambda.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.util.List;

@DynamoDbBean
public class TICFCRIStore {
    private String internalPairwiseId;
    private String interventionCode;
    private String interventionReason;
    private List<String> ci;
    private int errorStatus;
    private int sleep;

    @DynamoDbPartitionKey
    @DynamoDbAttribute("InternalPairwiseId")
    public String getInternalPairwiseId() {
        return internalPairwiseId;
    }

    public void setInternalPairwiseId(String internalPairwiseId) {
        this.internalPairwiseId = internalPairwiseId;
    }

    public TICFCRIStore withInternalPairwiseId(String internalPairwiseId) {
        this.internalPairwiseId = internalPairwiseId;
        return this;
    }

    @DynamoDbAttribute("CI")
    public List<String> getCi() {
        return ci;
    }

    public void setCi(List<String> ci) {
        this.ci = ci;
    }

    public TICFCRIStore withCi(List<String> ci) {
        this.ci = ci;
        return this;
    }

    @DynamoDbAttribute("InterventionCode")
    public String getInterventionCode() {
        return interventionCode;
    }

    public void setInterventionCode(String interventionCode) {
        this.interventionCode = interventionCode;
    }

    public TICFCRIStore withInterventionCode(String interventionCode) {
        this.interventionCode = interventionCode;
        return this;
    }

    @DynamoDbAttribute("InterventionReason")
    public String getInterventionReason() {
        return interventionReason;
    }

    public void setInterventionReason(String interventionReason) {
        this.interventionReason = interventionReason;
    }

    public TICFCRIStore withInterventionReason(String interventionReason) {
        this.interventionReason = interventionReason;
        return this;
    }

    @DynamoDbAttribute("ErrorStatus")
    public int getErrorStatus() { return errorStatus; }

    public void setErrorStatus(int errorStatus) {
        this.errorStatus = errorStatus;
    }

    public TICFCRIStore withErrorStatus(int errorStatus) {
        this.errorStatus = errorStatus;
        return this;
    }

    @DynamoDbAttribute("Sleep")
    public int getSleep() { return sleep; }

    public void setSleep(int sleep) {
        this.sleep = sleep;
    }

    public TICFCRIStore withSleep(int sleep) {
        this.sleep = sleep;
        return this;
    }
}
