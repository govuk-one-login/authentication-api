package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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

    @Test
    void anEmptySuccessShouldActAppropriately() {
        var ok = Result.emptySuccess();

        assertNull(ok.getSuccess());
        assertTrue(ok.isSuccess());
        assertFalse(ok.isFailure());
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

    @Nested
    class TapAndTapFailureTests {
        private ArrayList<String> logsEmitted;

        @BeforeEach
        void setup() {
            logsEmitted = new ArrayList<>();
        }

        @Test
        void tapShouldPerformASideEffectOnASuccessAndReturnOriginalResult() {
            var successValue = 1;
            var originalSuccess = Result.success(successValue);

            var tapResult =
                    originalSuccess.tap(i -> logFunction(String.format("Got success value %d", i)));

            assertLogged("Got success value 1");

            assertEquals(originalSuccess, tapResult);
        }

        @Test
        void tapShouldPerformMultipleSideEffectsOnASuccessAndReturnOriginalResult() {
            var successValue = 5;
            var originalSuccess = Result.success(successValue);
            var originalSumOfValues = 100;
            var sumOfSuccessesSoFar = new AtomicInteger(originalSumOfValues);

            var tapResult =
                    originalSuccess.tap(
                            i -> {
                                logFunction(String.format("Got success value %d", i));
                                sumOfSuccessesSoFar.set(sumOfSuccessesSoFar.get() + i);
                            });

            assertLogged("Got success value 5");

            assertEquals(originalSumOfValues + successValue, sumOfSuccessesSoFar.get());

            assertEquals(originalSuccess, tapResult);
        }

        @Test
        void tapShouldNotPerformASideEffectOnAFailureAndReturnOriginalResult() {
            var originalFailure = Result.<String, Integer>failure("some failure");

            var tapResult =
                    originalFailure.tap(i -> logFunction(String.format("Got success value %d", i)));

            assertLogsEmpty();
            assertEquals(originalFailure, tapResult);
        }

        @Test
        void tapFailureShouldNotPerformASideEffectOnASuccessAndReturnOriginalResult() {
            var successValue = 1;
            var originalSuccess = Result.success(successValue);
            var originalNumberOfFailures = 100;
            AtomicInteger numberOfFailuresSoFar = new AtomicInteger(originalNumberOfFailures);

            var tapFailureResult =
                    originalSuccess.tapFailure(
                            f -> numberOfFailuresSoFar.set(numberOfFailuresSoFar.get() + 1));

            assertEquals(originalNumberOfFailures, numberOfFailuresSoFar.get());

            assertEquals(originalSuccess, tapFailureResult);
        }

        @Test
        void tapFailureShouldPerformASideEffectOnAFailureAndReturnOriginalResult() {
            var originalFailure = Result.<String, Integer>failure("some failure");

            var originalNumberOfFailures = 100;
            AtomicInteger numberOfFailuresSoFar = new AtomicInteger(originalNumberOfFailures);

            var tapFailureResult =
                    originalFailure.tapFailure(
                            f -> numberOfFailuresSoFar.set(numberOfFailuresSoFar.get() + 1));

            assertEquals(originalNumberOfFailures + 1, numberOfFailuresSoFar.get());

            assertEquals(originalFailure, tapFailureResult);
        }

        @Test
        void tapFailureShouldPerformMultipleSideEffectsOnAFailureAndReturnOriginalResult() {
            var originalFailure = Result.<String, Integer>failure("some failure");

            var originalNumberOfFailures = 100;
            AtomicInteger numberOfFailuresSoFar = new AtomicInteger(originalNumberOfFailures);

            var tapFailureResult =
                    originalFailure.tapFailure(
                            f -> {
                                numberOfFailuresSoFar.set(numberOfFailuresSoFar.get() + 1);
                                logFunction(String.format("Got failure: %s", f));
                            });

            assertEquals(originalNumberOfFailures + 1, numberOfFailuresSoFar.get());

            assertLogged("Got failure: some failure");

            assertEquals(originalFailure, tapFailureResult);
        }

        private void logFunction(String s) {
            logsEmitted.add(s);
        }

        private void assertLogsEmpty() {
            assertEquals(0, logsEmitted.size());
        }

        private void assertLogged(String expected) {
            assertEquals(1, logsEmitted.size());
            assertEquals(expected, logsEmitted.get(0));
        }
    }

    @Nested
    class FlatTapTests {
        private ArrayList<String> logsEmitted;

        private Result<String, Boolean> addToLogsReturningSuccess(String logMessage) {
            return Result.success(logsEmitted.add(logMessage));
        }

        private Result<String, Boolean> addToLogsReturningFailure(
                String logMessage, String failureMessage) {
            logsEmitted.add(logMessage);
            return Result.failure(failureMessage);
        }

        @BeforeEach
        void setup() {
            logsEmitted = new ArrayList<>();
        }

        @Test
        void flatTapShouldExecuteActionAndReturnOriginalSuccessWhenActionSucceeds() {
            var successValue = 42;
            var originalSuccess = Result.<String, Integer>success(successValue);

            var result =
                    originalSuccess.flatTap(
                            i -> addToLogsReturningSuccess(String.format("Processing %d", i)));

            assertEquals(1, logsEmitted.size());
            assertEquals("Processing 42", logsEmitted.get(0));
            assertEquals(originalSuccess, result);
            assertTrue(result.isSuccess());
            assertEquals(successValue, result.getSuccess());
        }

        @Test
        void flatTapShouldPropagateFailureWhenActionFails() {
            var successValue = 42;
            var originalSuccess = Result.<String, Integer>success(successValue);
            var actionFailureMessage = "action failed";

            var result =
                    originalSuccess.flatTap(
                            i ->
                                    addToLogsReturningFailure(
                                            String.format("Processing %d", i),
                                            actionFailureMessage));

            assertEquals(1, logsEmitted.size());
            assertEquals("Processing 42", logsEmitted.get(0));
            assertTrue(result.isFailure());
            assertEquals(actionFailureMessage, result.getFailure());
        }

        @Test
        void flatTapShouldNotExecuteActionOnFailureAndReturnOriginalFailure() {
            var failureValue = "original failure";
            var originalFailure = Result.<String, Integer>failure(failureValue);

            var result =
                    originalFailure.flatTap(
                            i -> addToLogsReturningSuccess(String.format("Processing %d", i)));

            assertEquals(0, logsEmitted.size());
            assertEquals(originalFailure, result);
            assertTrue(result.isFailure());
            assertEquals(failureValue, result.getFailure());
        }

        @Test
        void flatTapShouldReturnOriginalSuccessNotActionSuccessValue() {
            var successValue = "original";
            var originalSuccess = Result.<String, String>success(successValue);

            var result =
                    originalSuccess.flatTap(
                            s -> Result.success("different success value that should be ignored"));

            assertTrue(result.isSuccess());
            assertEquals(successValue, result.getSuccess());
        }

        @Test
        void flatTapShouldChainMultipleActionsCorrectly() {
            var successValue = 10;
            var originalSuccess = Result.<String, Integer>success(successValue);

            var result =
                    originalSuccess
                            .flatTap(s -> addToLogsReturningSuccess("first action"))
                            .flatTap(s -> addToLogsReturningSuccess("second action"));

            assertEquals(2, logsEmitted.size());
            assertEquals("first action", logsEmitted.get(0));
            assertEquals("second action", logsEmitted.get(1));
            assertEquals(originalSuccess, result);
        }

        @Test
        void flatTapShouldShortCircuitOnFirstFailureInChain() {
            var successValue = 10;
            var originalSuccess = Result.<String, Integer>success(successValue);

            var failureMessageForFirstAction = "first failed";
            var result =
                    originalSuccess
                            .flatTap(
                                    i ->
                                            addToLogsReturningFailure(
                                                    "first action", failureMessageForFirstAction))
                            .flatTap(s -> addToLogsReturningSuccess("second action"));

            assertEquals(1, logsEmitted.size());
            assertEquals("first action", logsEmitted.get(0));
            assertTrue(result.isFailure());
            assertEquals(failureMessageForFirstAction, result.getFailure());
        }
    }
}
