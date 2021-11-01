package uk.gov.di.authentication.frontendapi.entity;

public class CheckUserExistsRequest extends BaseFrontendRequest {
    @Override
    public String toString() {
        return "CheckUserExistsRequest{" + "email='" + email + '\'' + '}';
    }
}
