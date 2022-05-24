package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;
import uk.gov.di.authentication.shared.serialization.EmailDeserializer;

@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class BaseFrontendRequest {
    @NotNull
    @Expose
    @SerializedName("email")
    @JsonAdapter(EmailDeserializer.class)
    protected String email;

    public String getEmail() {
        return email;
    }
}
