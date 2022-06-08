package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;

public class CommonPassword {

    private String password;

    @DynamoDBHashKey(attributeName = "Password")
    public String getPassword() {
        return password;
    }

    public CommonPassword setPassword(String password) {
        this.password = password;
        return this;
    }


}
