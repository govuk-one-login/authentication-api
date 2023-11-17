package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static uk.gov.di.orchestration.shared.helpers.RequestBodyHelper.parseRequestBody;

class RequestBodyHelperTest {

    @Test
    void takesLastValueIfMultipleInstancesOfKey() {

        var input = "key=one&key=two";

        assertThat(parseRequestBody(input), hasEntry("key", "two"));
    }
}
