#include "Copter.h"

#define MAX_FA_CHECK_FAIL 2

static uint8_t fail_counter = 0;

void Copter::check_flying_allowed()
{
    auto &odid = AP::opendroneid();
    uint8_t flight_status = odid.get_odid_status();
    char *flight_error = odid.get_odid_error();
    if (flight_status == DRONECAN_REMOTEID_ARMSTATUS_ODID_ARM_STATUS_FAIL_FLYING_NOT_ALLOWED ||
        flight_status == DRONECAN_REMOTEID_ARMSTATUS_ODID_ARM_STATUS_FAIL_GPS ||
        flight_status == DRONECAN_REMOTEID_ARMSTATUS_ODID_ARM_STATUS_FAIL_LOST_MODULE) {
        if (fail_counter >= MAX_FA_CHECK_FAIL) {
            flying_not_allowed_event(flight_error);
        }
        fail_counter++;
    } else {
        flying_not_allowed_off_event();
    }
}

void Copter::flying_not_allowed_off_event(void)
{
    if (!failsafe.non_allowed_area) {
        return;
    }
    failsafe.non_allowed_area = false;
    fail_counter = 0;
    if (AP_Notify::flags.flying_checks) {
        AP_Notify::flags.flying_checks = false;
        GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL, "FLDSMDFR: event cleared");
    }
    LOGGER_WRITE_ERROR(LogErrorSubsystem::FLYING_CHECKS, LogErrorCode::FAILSAFE_RESOLVED);
}

void Copter::flying_not_allowed_event(char *flight_error)
{
    failsafe.non_allowed_area = true;
    LOGGER_WRITE_ERROR(LogErrorSubsystem::FLYING_CHECKS, LogErrorCode::FAILSAFE_OCCURRED);
    if (!motors->armed()) {
        return;
    }
    if (flightmode->mode_number() == Mode::Number::RTL ||
        flightmode->mode_number() == Mode::Number::SMART_RTL ||
        flightmode->mode_number() == Mode::Number::LAND) {
        return;
    }
    set_mode_SmartRTL_or_RTL(ModeReason::FLYING_CHECKS);
    AP_Notify::flags.flying_checks = true;
    GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL, "FLDSMDFR: %s, changed to %s Mode", flight_error, flightmode->name());
}

bool Copter::is_flying_allowed(ModeReason reason)
{
    if (!failsafe.non_allowed_area) {
        return true;
    }
    switch (reason) {
    case ModeReason::EKF_FAILSAFE:
    case ModeReason::BATTERY_FAILSAFE:
    case ModeReason::TERRAIN_FAILSAFE:
    case ModeReason::DEADRECKON_FAILSAFE:
        return true;
    default:
        if (flightmode->mode_number() == Mode::Number::RTL ||
            flightmode->mode_number() == Mode::Number::SMART_RTL ||
            flightmode->mode_number() == Mode::Number::LAND) {
            GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL, "FLDSMDFR: not able to change flight mode");
            return false;
        }
        return true;
    }
}
