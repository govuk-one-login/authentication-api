package uk.gov.di.authentication.accountmigration;

import com.opencsv.bean.CsvBindByName;
import com.opencsv.bean.CsvCustomBindByName;

import java.time.LocalDateTime;

public class ImportRecord {

    @CsvBindByName(column = "email")
    private String email;

    @CsvBindByName(column = "encrypted_password")
    private String encryptedPassword;

    @CsvBindByName(column = "subject_identifier")
    private String subjectIdentifier;

    @CsvBindByName(column = "phone")
    private String phone;

    @CsvCustomBindByName(column = "created_at", converter = LocalDateConverter.class)
    private LocalDateTime createdAt;

    public String getEmail() {
        return email;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public String getSubjectIdentifier() {
        return subjectIdentifier;
    }

    public String getPhone() {
        return phone;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
}
