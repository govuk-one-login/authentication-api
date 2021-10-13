package uk.gov.di.authentication.accountmigration;

import com.opencsv.bean.CsvBindByName;

public class TestPassword {
    @CsvBindByName(column = "email")
    private String email;

    @CsvBindByName(column = "password")
    private String password;

    public String getEmail() {
        return email;
    }

    public TestPassword setEmail(String email) {
        this.email = email;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public TestPassword setPassword(String password) {
        this.password = password;
        return this;
    }
}
