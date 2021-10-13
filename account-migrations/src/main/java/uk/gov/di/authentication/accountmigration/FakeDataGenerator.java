package uk.gov.di.authentication.accountmigration;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.opencsv.bean.HeaderColumnNameMappingStrategy;
import com.opencsv.bean.StatefulBeanToCsv;
import com.opencsv.bean.StatefulBeanToCsvBuilder;
import com.opencsv.exceptions.CsvDataTypeMismatchException;
import com.opencsv.exceptions.CsvRequiredFieldEmptyException;
import org.apache.commons.collections.comparators.FixedOrderComparator;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static java.lang.String.format;

public class FakeDataGenerator {
    private static final int RECORD_COUNT = 70000;
    private static final String CSV_LOCATION = "data_transfer_test_account.csv";
    private static final String PASSWORD_LOCATION = "test_account_passwords.csv";
    private static final String PEPPER = generateRandomSpecialCharacters(32);

    public static void main(String[] args) {
        try {
            List<ImportRecord> importRecordList = new ArrayList<>();
            List<TestPassword> testPasswordList = new ArrayList<>();

            SecureRandom rng = new SecureRandom();
            for (int i = 0; i < RECORD_COUNT; i++) {
                String password = generateRandomSpecialCharacters(10);
                char[] passwordWithPepper = (password + PEPPER).toCharArray();
                String hashed = OpenBSDBCrypt.generate(passwordWithPepper, rng.generateSeed(16), 5);
                String email = format("hello+%d@gov.uk", i);
                ImportRecord record =
                        new ImportRecord()
                                .setEmail(email)
                                .setPhone(format("+441234%06d", i))
                                .setEncryptedPassword(hashed)
                                .setSubjectIdentifier(new Subject().toString())
                                .setCreatedAt(LocalDateTime.now());

                importRecordList.add(record);

                TestPassword testPassword =
                        new TestPassword().setEmail(email).setPassword(password);
                testPasswordList.add(testPassword);
            }

            saveImportFile(importRecordList);
            savePasswordFile(testPasswordList);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void saveImportFile(List<ImportRecord> importRecordList)
            throws IOException, CsvRequiredFieldEmptyException, CsvDataTypeMismatchException {
        FileWriter writer = new FileWriter(CSV_LOCATION);

        HeaderColumnNameMappingStrategy<ImportRecord> mappingStrategy =
                new HeaderColumnNameMappingStrategy<>();
        mappingStrategy.setColumnOrderOnWrite(
                new FixedOrderComparator(
                        new String[] {
                            "EMAIL",
                            "ENCRYPTED_PASSWORD",
                            "PHONE",
                            "SUBJECT_IDENTIFIER",
                            "CREATED_AT"
                        }));
        mappingStrategy.setType(ImportRecord.class);

        StatefulBeanToCsvBuilder<ImportRecord> builder = new StatefulBeanToCsvBuilder<>(writer);
        StatefulBeanToCsv<ImportRecord> beanWriter =
                builder.withMappingStrategy(mappingStrategy).build();

        beanWriter.write(importRecordList);

        writer.close();
    }

    private static void savePasswordFile(List<TestPassword> testPasswordList)
            throws IOException, CsvRequiredFieldEmptyException, CsvDataTypeMismatchException {
        FileWriter writer = new FileWriter(PASSWORD_LOCATION);

        HeaderColumnNameMappingStrategy<TestPassword> mappingStrategy =
                new HeaderColumnNameMappingStrategy<>();
        mappingStrategy.setColumnOrderOnWrite(
                new FixedOrderComparator(new String[] {"EMAIL", "PASSWORD"}));
        mappingStrategy.setType(TestPassword.class);

        StatefulBeanToCsvBuilder<TestPassword> builder = new StatefulBeanToCsvBuilder<>(writer);
        StatefulBeanToCsv<TestPassword> beanWriter =
                builder.withMappingStrategy(mappingStrategy).build();

        beanWriter.write(testPasswordList);

        writer.close();
    }

    public static String generateRandomSpecialCharacters(int length) {
        return RandomStringUtils.random(length, true, true);
    }
}
