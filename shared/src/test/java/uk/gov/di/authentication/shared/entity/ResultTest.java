package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResultTest {
    @Test
    void aFailureShouldActAppropriately() {
        var failureValue = "failure";
        var failure = Result.failure(failureValue);

        assertEquals(failureValue, failure.getFailure());
        assertTrue(failure.isFailure());
        assertFalse(failure.isSuccess());
        assertThrows(IllegalStateException.class, failure::getSuccess);
    }

    @Test
    void aSuccessShouldActAppropriately() {
        var successValue = "success";
        var success = Result.success(successValue);

        assertEquals(successValue, success.getSuccess());
        assertFalse(success.isFailure());
        assertTrue(success.isSuccess());
        assertThrows(IllegalStateException.class, success::getFailure);
    }

    @Nested
    class SequenceSuccessTests {
        @Test
        void sequenceSuccessShouldBeAbleToTransformAListOfSuccessIntoASuccessOfAList() {
            var results = List.of(Result.success(1), Result.success(2), Result.success(3));

            var expectedAfterSequencing = Result.success(List.of(1, 2, 3));

            assertEquals(expectedAfterSequencing, Result.sequenceSuccess(results));
        }

        @Test
        void sequenceSuccessShouldReturnAFailureBasedOnTheFirstFailureInTheList() {
            var firstFailureValue = "firstFailure";
            var secondFailureValue = "secondFailure";
            List<Result<String, Integer>> results =
                    List.of(
                            Result.success(1),
                            Result.failure(firstFailureValue),
                            Result.success(2),
                            Result.failure(secondFailureValue));

            assertEquals(Result.failure(firstFailureValue), Result.sequenceSuccess(results));
        }
    }

    @Nested
    class MapTests {
        @Test
        void aSuccessShouldSuccessfullyMapToASuccessOfTheSameType() {
            var number = 1;
            var success = Result.success(number);

            var result = success.map(n -> n + 1);
            assertEquals(Result.success(2), result);
        }

        @Test
        void aSuccessShouldSuccessfullyMapToASuccessOfADifferentType() {
            var number = 1;
            var success = Result.success(number);

            var result = success.map(Object::toString);
            assertEquals(Result.success("1"), result);
        }

        @Test
        void aSuccessShouldBeAbleToProduceSideEffectsFromWithinTheFunctionPassedToIt() {
            var logs = new ArrayList<>();
            var number = 1;
            var success = Result.success(number);

            var result =
                    success.map(
                            n -> {
                                logs.add(format("Processing number %d", n));
                                return n + 1;
                            });
            assertEquals(Result.success(2), result);
            assertEquals(1, logs.size());
            assertEquals("Processing number 1", logs.get(0));
        }

        @Test
        void aFailureShouldReturnTheFailureWhenMappedWithNoOtherEffects() {
            var logs = new ArrayList<>();
            var failure = Result.<String, Integer>failure("This failed");

            var result =
                    failure.map(
                            n -> {
                                logs.add(format("Processing number %d", n));
                                return n + 1;
                            });
            assertEquals(failure, result);
            assertEquals(0, logs.size());
        }
    }

    @Nested
    class FlatMapTests {
        @Test
        void flatMapShouldSuccessfullyTransformASuccessIntoANewResultAndCarryOutAnySideEffects() {
            var number = 1;
            var success = Result.success(number);
            var logs = new ArrayList<>();

            var result =
                    success.flatMap(
                            n -> {
                                logs.add(format("Processing number %d", n));
                                return Result.success(n + 1);
                            });
            assertEquals(Result.success(2), result);
            assertEquals(1, logs.size());
            assertEquals("Processing number 1", logs.get(0));
        }

        @Test
        void flatMapShouldReturnAFailureWithNoOtherEffectsWhenActingOnAFailure() {
            var failureString = "This is a failure";
            var failure = Result.<String, Integer>failure(failureString);
            var logs = new ArrayList<>();

            var result =
                    failure.flatMap(
                            n -> {
                                logs.add(format("Processing number %d", n));
                                return Result.success(n + 1);
                            });
            assertEquals(failure, result);
            assertEquals(0, logs.size());
        }
    }

    @Nested
    class MapFailureTests {
        @Test
        void shouldReturnASuccessWithNoSideEffects() {
            var successValue = 1;
            var success = Result.<String, Integer>success(successValue);
            var failureLogs = new ArrayList<>();

            var mapFailureResult =
                    success.mapFailure(
                            s -> {
                                failureLogs.add(format("Found failure %s", s));
                                return s.length();
                            });

            assertEquals(0, failureLogs.size());
            assertEquals(Result.<Integer, Integer>success(successValue), mapFailureResult);
        }

        @Test
        void shouldSuccessfullyTransformALeftHandValue() {
            var failureString = "abc";
            var failure = Result.<String, Integer>failure(failureString);
            var failureLogs = new ArrayList<>();

            var mapFailureResult =
                    failure.mapFailure(
                            s -> {
                                failureLogs.add(format("Found failure %s", s));
                                return s.length();
                            });

            assertEquals(1, failureLogs.size());
            assertEquals("Found failure abc", failureLogs.get(0));
            assertEquals(
                    Result.<Integer, Integer>failure(failureString.length()), mapFailureResult);
        }
    }
}
