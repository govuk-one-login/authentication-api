package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.serialization.EmailDeserializer;
import uk.gov.di.authentication.shared.validation.Required;

public abstract class BaseFrontendRequest {
    @Required
    @Expose
    @SerializedName("email")
    @JsonAdapter(EmailDeserializer.class)
    protected String email;

    public String getEmail() {
        return email;
    }
}
