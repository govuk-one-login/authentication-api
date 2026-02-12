package uk.gov.di.authentication.frontendapi.helpers;

import org.mockito.invocation.InvocationOnMock;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.*;

import java.util.function.Function;

public class PermissionMockHelper {

    @SuppressWarnings("unchecked")
    public static <T> Result<DecisionError, T> executePermitted(
            InvocationOnMock inv, PermittedData data) {
        Function<PermittedData, T> lambda = inv.getArgument(2);
        return Result.success(lambda.apply(data));
    }

    @SuppressWarnings("unchecked")
    public static <T> Result<DecisionError, T> executeTemporarilyLockedOut(
            InvocationOnMock inv, TemporarilyLockedOutData data) {
        Function<TemporarilyLockedOutData, T> lambda = inv.getArgument(3);
        return Result.success(lambda.apply(data));
    }

    @SuppressWarnings("unchecked")
    public static <T> Result<DecisionError, T> executeReauthLockedOut(
            InvocationOnMock inv, ReauthLockedOutData data) {
        Function<ReauthLockedOutData, T> lambda = inv.getArgument(3);
        return Result.success(lambda.apply(data));
    }

    @SuppressWarnings("unchecked")
    public static <T> Result<DecisionError, T> executeReauthLockedOutForPassword(
            InvocationOnMock inv, ReauthLockedOutData data) {
        Function<ReauthLockedOutData, T> lambda = inv.getArgument(4);
        return Result.success(lambda.apply(data));
    }

    @SuppressWarnings("unchecked")
    public static <T> Result<DecisionError, T> executeIndefinitelyLockedOut(
            InvocationOnMock inv, IndefinitelyLockedOutData data) {
        Function<IndefinitelyLockedOutData, T> lambda = inv.getArgument(4);
        return Result.success(lambda.apply(data));
    }
}
