package uk.gov.di.authentication.accountdata.entity.passkey;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.authentication.accountdata.constants.AccountDataConstants;
import uk.gov.di.authentication.accountdata.entity.Authenticator;

import java.util.List;

@DynamoDbBean
public class Passkey extends Authenticator<Passkey> {

    public static final String ATTRIBUTE_PASSKEY_AAGUID = "PasskeyAaguid";
    public static final String ATTRIBUTE_PASSKEY_IS_ATTESTED = "PasskeyIsAttested";
    public static final String ATTRIBUTE_PASSKEY_SIGN_COUNT = "PasskeySignCount";
    public static final String ATTRIBUTE_PASSKEY_TRANSPORTS = "PasskeyTransports";
    public static final String ATTRIBUTE_PASSKEY_BACKUP_ELIGIBLE = "PasskeyBackupEligible";
    public static final String ATTRIBUTE_PASSKEY_BACKED_UP = "PasskeyBackedUp";

    private String passkeyAaguid;
    private boolean passkeyIsAttested;
    private int passkeySignCount;
    private List<String> passkeyTransports;
    private boolean passkeyBackupEligible;
    private boolean passkeyBackedUp;

    @Override
    protected Passkey self() {
        return this;
    }

    @Override
    public String getType() {
        return AccountDataConstants.PASSKEY_TYPE;
    }

    @DynamoDbAttribute(ATTRIBUTE_PASSKEY_AAGUID)
    public String getPasskeyAaguid() {
        return passkeyAaguid;
    }

    public void setPasskeyAaguid(String passkeyAaguid) {
        this.passkeyAaguid = passkeyAaguid;
    }

    public Passkey withPasskeyAaguid(String passkeyAaguid) {
        this.passkeyAaguid = passkeyAaguid;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_PASSKEY_IS_ATTESTED)
    public boolean getPasskeyIsAttested() {
        return passkeyIsAttested;
    }

    public void setPasskeyIsAttested(boolean passkeyIsAttested) {
        this.passkeyIsAttested = passkeyIsAttested;
    }

    public Passkey withPasskeyIsAttested(boolean passkeyIsAttested) {
        this.passkeyIsAttested = passkeyIsAttested;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_PASSKEY_SIGN_COUNT)
    public int getPasskeySignCount() {
        return passkeySignCount;
    }

    public void setPasskeySignCount(int passkeySignCount) {
        this.passkeySignCount = passkeySignCount;
    }

    public Passkey withPasskeySignCount(int passkeySignCount) {
        this.passkeySignCount = passkeySignCount;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_PASSKEY_TRANSPORTS)
    public List<String> getPasskeyTransports() {
        return passkeyTransports;
    }

    public void setPasskeyTransports(List<String> passkeyTransports) {
        this.passkeyTransports = passkeyTransports;
    }

    public Passkey withPasskeyTransports(List<String> passkeyTransports) {
        this.passkeyTransports = passkeyTransports;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_PASSKEY_BACKUP_ELIGIBLE)
    public boolean getPasskeyBackupEligible() {
        return passkeyBackupEligible;
    }

    public void setPasskeyBackupEligible(boolean passkeyBackupEligible) {
        this.passkeyBackupEligible = passkeyBackupEligible;
    }

    public Passkey withPasskeyBackupEligible(boolean passkeyBackupEligible) {
        this.passkeyBackupEligible = passkeyBackupEligible;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_PASSKEY_BACKED_UP)
    public boolean getPasskeyBackedUp() {
        return passkeyBackedUp;
    }

    public void setPasskeyBackedUp(boolean passkeyBackedUp) {
        this.passkeyBackedUp = passkeyBackedUp;
    }

    public Passkey withPasskeyBackedUp(boolean passkeyBackedUp) {
        this.passkeyBackedUp = passkeyBackedUp;
        return this;
    }
}
