package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBIndexHashKey;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import uk.gov.di.authentication.shared.dynamodb.DynamoDBItem;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserProfile implements DynamoDBItem {

    public static final String ATTRIBUTE_EMAIL = "Email";
    public static final String ATTRIBUTE_SUBJECT_ID = "SubjectID";
    public static final String ATTRIBUTE_EMAIL_VERIFIED = "EmailVerified";
    public static final String ATTRIBUTE_PHONE_NUMBER = "PhoneNumber";
    public static final String ATTRIBUTE_PHONE_NUMBER_VERIFIED = "PhoneNumberVerified";
    public static final String ATTRIBUTE_CREATED = "Created";
    public static final String ATTRIBUTE_UPDATED = "Updated";
    public static final String ATTRIBUTE_TERMS_AND_CONDITIONS = "termsAndConditions";
    public static final String ATTRIBUTE_CLIENT_CONSENT = "ClientConsent";
    public static final String ATTRIBUTE_PUBLIC_SUBJECT_ID = "PublicSubjectID";
    public static final String ATTRIBUTE_LEGACY_SUBJECT_ID = "LegacySubjectID";
    public static final String ATTRIBUTE_SALT = "salt";
    public static final String ATTRIBUTE_ACCOUNT_VERIFIED = "accountVerified";

    private String email;
    private String subjectID;
    private boolean emailVerified;
    private String phoneNumber;
    private List<ClientConsent> clientConsent;
    private boolean phoneNumberVerified;
    private String created;
    private String updated;
    private TermsAndConditions termsAndConditions;
    private String publicSubjectID;
    private String legacySubjectID;
    private ByteBuffer salt;
    private Boolean accountVerified = null;

    public UserProfile() {}

    @DynamoDBHashKey(attributeName = ATTRIBUTE_EMAIL)
    public String getEmail() {
        return email;
    }

    public UserProfile setEmail(String email) {
        this.email = email;
        return this;
    }

    @DynamoDBIndexHashKey(
            globalSecondaryIndexName = "SubjectIDIndex",
            attributeName = ATTRIBUTE_SUBJECT_ID)
    public String getSubjectID() {
        return subjectID;
    }

    public UserProfile setSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_EMAIL_VERIFIED)
    public boolean isEmailVerified() {
        return emailVerified;
    }

    public UserProfile setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_PHONE_NUMBER)
    public String getPhoneNumber() {
        return phoneNumber;
    }

    public UserProfile setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_PHONE_NUMBER_VERIFIED)
    public boolean isPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public UserProfile setPhoneNumberVerified(boolean phoneNumberVerified) {
        this.phoneNumberVerified = phoneNumberVerified;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_CREATED)
    public String getCreated() {
        return created;
    }

    public UserProfile setCreated(String created) {
        this.created = created;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_UPDATED)
    public String getUpdated() {
        return updated;
    }

    public UserProfile setUpdated(String updated) {
        this.updated = updated;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_TERMS_AND_CONDITIONS)
    public TermsAndConditions getTermsAndConditions() {
        return termsAndConditions;
    }

    public UserProfile setTermsAndConditions(TermsAndConditions termsAndConditions) {
        this.termsAndConditions = termsAndConditions;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_CLIENT_CONSENT)
    public List<ClientConsent> getClientConsent() {
        return clientConsent;
    }

    public UserProfile setClientConsent(List<ClientConsent> clientConsent) {
        this.clientConsent = clientConsent;
        return this;
    }

    public UserProfile setClientConsent(ClientConsent consent) {
        if (this.clientConsent == null) {
            this.clientConsent = List.of(consent);
        } else {
            this.clientConsent.removeIf(t -> t.getClientId().equals(consent.getClientId()));
            this.clientConsent.add(consent);
        }
        return this;
    }

    @DynamoDBIndexHashKey(
            globalSecondaryIndexName = "PublicSubjectIDIndex",
            attributeName = ATTRIBUTE_PUBLIC_SUBJECT_ID)
    public String getPublicSubjectID() {
        return publicSubjectID;
    }

    public UserProfile setPublicSubjectID(String publicSubjectID) {
        this.publicSubjectID = publicSubjectID;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_LEGACY_SUBJECT_ID)
    public String getLegacySubjectID() {
        return legacySubjectID;
    }

    public UserProfile setLegacySubjectID(String legacySubjectID) {
        this.legacySubjectID = legacySubjectID;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_SALT)
    public ByteBuffer getSalt() {
        return salt;
    }

    public UserProfile setSalt(ByteBuffer salt) {
        this.salt = salt;
        return this;
    }

    public UserProfile setSalt(byte[] salt) {
        this.salt = ByteBuffer.wrap(salt);
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_ACCOUNT_VERIFIED)
    public Boolean getAccountVerified() {
        return accountVerified;
    }

    public UserProfile setAccountVerified(Boolean accountVerified) {
        this.accountVerified = accountVerified;
        return this;
    }

    @Override
    public Map<String, AttributeValue> toItem() {
        Map<String, AttributeValue> attributes = new HashMap<>();
        if (getEmail() != null) attributes.put(ATTRIBUTE_EMAIL, new AttributeValue(getEmail()));
        if (getSubjectID() != null)
            attributes.put(ATTRIBUTE_SUBJECT_ID, new AttributeValue(getSubjectID()));
        attributes.put(
                ATTRIBUTE_EMAIL_VERIFIED,
                new AttributeValue().withN(isEmailVerified() ? "1" : "0"));
        if (getPhoneNumber() != null)
            attributes.put(ATTRIBUTE_PHONE_NUMBER, new AttributeValue(getPhoneNumber()));
        attributes.put(
                ATTRIBUTE_PHONE_NUMBER_VERIFIED,
                new AttributeValue().withN(isPhoneNumberVerified() ? "1" : "0"));
        if (getCreated() != null)
            attributes.put(ATTRIBUTE_CREATED, new AttributeValue(getCreated()));
        if (getUpdated() != null)
            attributes.put(ATTRIBUTE_UPDATED, new AttributeValue(getUpdated()));
        if (getTermsAndConditions() != null)
            attributes.put(
                    ATTRIBUTE_TERMS_AND_CONDITIONS, getTermsAndConditions().toAttributeValue());
        if (getClientConsent() != null) {
            Collection<AttributeValue> consents = new ArrayList<>();
            getClientConsent().forEach(c -> consents.add(c.toAttributeValue()));
            attributes.put(ATTRIBUTE_CLIENT_CONSENT, new AttributeValue().withL(consents));
        }
        if (getPublicSubjectID() != null)
            attributes.put(ATTRIBUTE_PUBLIC_SUBJECT_ID, new AttributeValue(getPublicSubjectID()));
        if (getLegacySubjectID() != null)
            attributes.put(ATTRIBUTE_LEGACY_SUBJECT_ID, new AttributeValue(getLegacySubjectID()));
        if (getSalt() != null)
            attributes.put(ATTRIBUTE_SALT, new AttributeValue().withB(getSalt()));
        if (getAccountVerified() != null) {
            attributes.put(
                    ATTRIBUTE_ACCOUNT_VERIFIED,
                    new AttributeValue().withBOOL(getAccountVerified()));
        }
        return attributes;
    }
}
