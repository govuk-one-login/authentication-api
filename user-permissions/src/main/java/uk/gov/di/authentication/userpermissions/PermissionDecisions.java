package uk.gov.di.authentication.userpermissions;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.IndefinitelyLockedOutData;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;
import uk.gov.di.authentication.userpermissions.entity.PermittedData;
import uk.gov.di.authentication.userpermissions.entity.ReauthLockedOutData;
import uk.gov.di.authentication.userpermissions.entity.TemporarilyLockedOutData;

import java.util.function.Function;

public interface PermissionDecisions {
    <R> Result<DecisionError, R> canReceiveEmailAddress(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<ReauthLockedOutData, R> onReauthLockedOut);

    <R> Result<DecisionError, R> canSendEmailOtpNotification(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut);

    <R> Result<DecisionError, R> canVerifyEmailOtp(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut);

    <R> Result<DecisionError, R> canReceivePassword(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut,
            Function<ReauthLockedOutData, R> onReauthLockedOut);

    <R> Result<DecisionError, R> canSendSmsOtpNotification(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut,
            Function<IndefinitelyLockedOutData, R> onIndefinitelyLockedOut);

    <R> Result<DecisionError, R> canVerifyMfaOtp(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut);

    <R> Result<DecisionError, R> canStartJourney(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<ReauthLockedOutData, R> onReauthLockedOut);
}
