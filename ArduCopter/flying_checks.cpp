#include "Copter.h"

#if AP_OPENDRONEID_ENABLED

#define MAX_FA_CHECK_FAIL 2

static uint8_t fail_counter = 0;

void Copter::check_flying_allowed()
{
    // only a real zone hit reacts in flight; FAIL_GPS and FAIL_LOST_MODULE only block arming (pre_arm_check)
    if (AP::opendroneid().get_odid_status() != DRONECAN_REMOTEID_ARMSTATUS_ODID_ARM_STATUS_FAIL_FLYING_NOT_ALLOWED) {
        fail_counter = 0;
        return;
    }
    // needs MAX_FA_CHECK_FAIL + 1 failures in a row; saturate so the counter never wraps
    if (fail_counter < MAX_FA_CHECK_FAIL) {
        fail_counter++;
        return;
    }
    flying_not_allowed_event();
}

// called from disarm: the zone lock holds until then (user 2026-11-06)
void Copter::flying_not_allowed_off_event(void)
{
    if (!failsafe.non_allowed_area) {
        return;
    }
    failsafe.non_allowed_area = false;
    AP_Notify::flags.flying_checks = false;
    GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL, "FLDSMDFR: event cleared");
    LOGGER_WRITE_ERROR(LogErrorSubsystem::FLYING_CHECKS, LogErrorCode::FAILSAFE_RESOLVED);
}

void Copter::flying_not_allowed_event()
{
    // never start a zone reaction without a position (no forced LAND); the next 2 Hz tick retries
    // (position_ok() is also false during an EKF failsafe)
    if (!motors->armed() || !position_ok()) {
        return;
    }
    switch (flightmode->mode_number()) {
    case Mode::Number::RTL:
    case Mode::Number::SMART_RTL:
    case Mode::Number::LAND:
        return;
    default:
        break;
    }
    // SmartRTL, else RTL; no LAND fallback, a failed switch is retried next tick
    if (!set_mode(Mode::Number::SMART_RTL, ModeReason::FLYING_CHECKS) &&
        !set_mode(Mode::Number::RTL, ModeReason::FLYING_CHECKS)) {
        return;
    }
    AP_Notify::events.failsafe_mode_change = 1;
    char flight_error[51]; // ArmStatus error is uint8[<=50], not NUL-terminated
    AP::opendroneid().get_odid_error(flight_error, sizeof(flight_error));
    GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL, "FLDSMDFR: %s, changed to %s Mode", flight_error, flightmode->name());
    // lock and log once per zone event (status 3 keeps arriving at 2 Hz)
    if (!failsafe.non_allowed_area) {
        failsafe.non_allowed_area = true;
        AP_Notify::flags.flying_checks = true;
        LOGGER_WRITE_ERROR(LogErrorSubsystem::FLYING_CHECKS, LogErrorCode::FAILSAFE_OCCURRED);
    }
}

// true while RTL/SmartRTL holds at RTL_ALT_FINAL > 0 above home instead of landing
bool Copter::zone_rtl_final_hover()
{
#if MODE_RTL_ENABLED
    if (flightmode == &mode_rtl &&
        mode_rtl.state() == ModeRTL::SubMode::FINAL_DESCENT && mode_rtl.state_complete()) {
        return true;
    }
#endif
#if MODE_SMARTRTL_ENABLED
    if (flightmode == &mode_smartrtl && mode_smartrtl.final_hover()) {
        return true;
    }
#endif
    return false;
}

// zone lock: from the zone event until disarm, also after a failsafe changed the mode (user 2026-11-06).
// Failsafes and the zone event itself may change the mode; the pilot may only pick LAND from the final hover.
bool Copter::is_flying_allowed(Mode::Number mode, ModeReason reason)
{
    if (!failsafe.non_allowed_area) {
        return true;
    }
    switch (reason) {
    case ModeReason::FLYING_CHECKS:
    case ModeReason::EKF_FAILSAFE:
    case ModeReason::BATTERY_FAILSAFE:
    case ModeReason::TERRAIN_FAILSAFE:
    case ModeReason::DEADRECKON_FAILSAFE:
        return true;
    default:
        break;
    }
    if (mode == Mode::Number::LAND && zone_rtl_final_hover()) {
        return true;
    }
    GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL, "FLDSMDFR: not able to change flight mode");
    return false;
}

#endif // AP_OPENDRONEID_ENABLED
