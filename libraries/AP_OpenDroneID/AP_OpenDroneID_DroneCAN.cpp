/*
 * This file is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
  DroneCAN support for OpenDroneID
 */

#include "AP_OpenDroneID.h"

#if AP_OPENDRONEID_ENABLED

#include <AP_DroneCAN/AP_DroneCAN.h>
#include <AP_CheckFirmware/monocypher.h>
#include <AP_CheckFirmware/AP_CheckFirmware.h>

extern const AP_HAL::HAL& hal;

#if HAL_ENABLE_DRONECAN_DRIVERS
#include <GCS_MAVLink/GCS.h>

static Canard::Publisher<dronecan_remoteid_Location>* dc_location[HAL_MAX_CAN_PROTOCOL_DRIVERS];
static Canard::Publisher<dronecan_remoteid_BasicID>* dc_basic_id[HAL_MAX_CAN_PROTOCOL_DRIVERS];
static Canard::Publisher<dronecan_remoteid_SelfID>* dc_self_id[HAL_MAX_CAN_PROTOCOL_DRIVERS];
static Canard::Publisher<dronecan_remoteid_System>* dc_system[HAL_MAX_CAN_PROTOCOL_DRIVERS];
static Canard::Publisher<dronecan_remoteid_OperatorID>* dc_operator_id[HAL_MAX_CAN_PROTOCOL_DRIVERS];

static void handle_arm_status(AP_DroneCAN* ap_dronecan, const CanardRxTransfer &transfer, const dronecan_aurelia_remoteid_Status &msg);

struct SecureCmdAuthCtx {
    static void auth_cb(AP_OpenDroneID *self, const CanardRxTransfer &transfer,
                        const dronecan_remoteid_SecureCommandResponse &rsp) {
        if (rsp.operation != DRONECAN_REMOTEID_SECURECOMMAND_REQUEST_SECURE_COMMAND_AUTH_CHALLENGE) {
            GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "FLDSMDFR: Unexpected response from module (node %u)",
                          transfer.source_node_id);
            return;
        }
        if (rsp.data.len >= 64) {
            self->set_auth_response(transfer.source_node_id, rsp.data.data, rsp.data.len);
        } else {
            GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "FLDSMDFR: module sent incomplete response (node %u)",
                          transfer.source_node_id);
        }
    }
    Canard::ArgCallback<AP_OpenDroneID, dronecan_remoteid_SecureCommandResponse> cb;
    Canard::Client<dronecan_remoteid_SecureCommandResponse> client;

    SecureCmdAuthCtx(AP_OpenDroneID *self, AP_DroneCAN *uavcan) :
        cb(self, auth_cb),
        client(uavcan->get_canard_iface(), cb) {}
};
static SecureCmdAuthCtx *auth_ctx[HAL_MAX_CAN_PROTOCOL_DRIVERS];

struct SecureCmdKeygenCtx {
    static void keygen_cb(AP_OpenDroneID *self, const CanardRxTransfer &transfer,
                          const dronecan_remoteid_SecureCommandResponse &rsp) {
        if (rsp.operation != DRONECAN_REMOTEID_SECURECOMMAND_REQUEST_SECURE_COMMAND_GENERATE_RID_KEY) {
            return;
        }
        if (rsp.result == DRONECAN_REMOTEID_SECURECOMMAND_RESPONSE_RESULT_ACCEPTED && rsp.data.len >= 32) {
            GCS_SEND_TEXT(MAV_SEVERITY_INFO, "FLDSMDFR: key generated successfully (node %u)",
                          transfer.source_node_id);
            self->set_rid_public_key(rsp.data.data);
        } else {
            GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "FLDSMDFR: key generation failed (node %u)",
                          transfer.source_node_id);
        }
    }
    Canard::ArgCallback<AP_OpenDroneID, dronecan_remoteid_SecureCommandResponse> cb;
    Canard::Client<dronecan_remoteid_SecureCommandResponse> client;

    SecureCmdKeygenCtx(AP_OpenDroneID *self, AP_DroneCAN *uavcan) :
        cb(self, keygen_cb),
        client(uavcan->get_canard_iface(), cb) {}
};
static SecureCmdKeygenCtx *keygen_ctx[HAL_MAX_CAN_PROTOCOL_DRIVERS];

struct SecureCmdOTACtx {
    static void ota_chunk_cb(AP_OpenDroneID *self, const CanardRxTransfer &transfer,
                             const dronecan_remoteid_SecureCommandResponse &rsp) {
        if (rsp.operation != DRONECAN_REMOTEID_SECURECOMMAND_REQUEST_SECURE_COMMAND_OTA_CHUNK) {
            return;
        }
        bool success = (rsp.result == DRONECAN_REMOTEID_SECURECOMMAND_RESPONSE_RESULT_ACCEPTED);
#if AP_CHECK_FIRMWARE_ENABLED && HAL_GCS_ENABLED
        AP_CheckFirmware::ota_dronecan_raw_result = rsp.result;
        AP_CheckFirmware::set_ota_chunk_done(success);
#endif
        if (!success) {
            GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "FLDSMDFR: OTA chunk rejected by module (node %u)",
                          transfer.source_node_id);
        }
    }
    Canard::ArgCallback<AP_OpenDroneID, dronecan_remoteid_SecureCommandResponse> cb;
    Canard::Client<dronecan_remoteid_SecureCommandResponse> client;

    SecureCmdOTACtx(AP_OpenDroneID *self, AP_DroneCAN *uavcan) :
        cb(self, ota_chunk_cb),
        client(uavcan->get_canard_iface(), cb) {}
};
static SecureCmdOTACtx *ota_ctx[HAL_MAX_CAN_PROTOCOL_DRIVERS];

void AP_OpenDroneID::dronecan_init(AP_DroneCAN *uavcan)
{
    const uint8_t driver_index = uavcan->get_driver_index();
    driver_mask = 1U<<driver_index;
    if (dronecan_done_init & driver_mask) {
        // already initialised
        return;
    }

    dc_location[driver_index] = NEW_NOTHROW Canard::Publisher<dronecan_remoteid_Location>(uavcan->get_canard_iface());
    if (dc_location[driver_index] == nullptr) {
        goto alloc_failed;
    }
    dc_location[driver_index]->set_timeout_ms(20);
    dc_location[driver_index]->set_priority(CANARD_TRANSFER_PRIORITY_LOW);

    dc_basic_id[driver_index] = NEW_NOTHROW Canard::Publisher<dronecan_remoteid_BasicID>(uavcan->get_canard_iface());
    if (dc_basic_id[driver_index] == nullptr) {
        goto alloc_failed;
    }
    dc_basic_id[driver_index]->set_timeout_ms(20);
    dc_basic_id[driver_index]->set_priority(CANARD_TRANSFER_PRIORITY_LOW);

    dc_self_id[driver_index] = NEW_NOTHROW Canard::Publisher<dronecan_remoteid_SelfID>(uavcan->get_canard_iface());
    if (dc_self_id[driver_index] == nullptr) {
        goto alloc_failed;
    }
    dc_self_id[driver_index]->set_timeout_ms(20);
    dc_self_id[driver_index]->set_priority(CANARD_TRANSFER_PRIORITY_LOW);

    dc_system[driver_index] = NEW_NOTHROW Canard::Publisher<dronecan_remoteid_System>(uavcan->get_canard_iface());
    if (dc_system[driver_index] == nullptr) {
        goto alloc_failed;
    }
    dc_system[driver_index]->set_timeout_ms(20);
    dc_system[driver_index]->set_priority(CANARD_TRANSFER_PRIORITY_LOW);

    dc_operator_id[driver_index] = NEW_NOTHROW Canard::Publisher<dronecan_remoteid_OperatorID>(uavcan->get_canard_iface());
    if (dc_operator_id[driver_index] == nullptr) {
        goto alloc_failed;
    }
    dc_operator_id[driver_index]->set_timeout_ms(20);
    dc_operator_id[driver_index]->set_priority(CANARD_TRANSFER_PRIORITY_LOW);

    if (Canard::allocate_sub_arg_callback(uavcan, &handle_arm_status, driver_index) == nullptr)
    {
        goto alloc_failed;
    }

    auth_ctx[driver_index] = NEW_NOTHROW SecureCmdAuthCtx(this, uavcan);
    if (auth_ctx[driver_index] == nullptr) {
        goto alloc_failed;
    }

    keygen_ctx[driver_index] = NEW_NOTHROW SecureCmdKeygenCtx(this, uavcan);
    if (keygen_ctx[driver_index] == nullptr) {
        goto alloc_failed;
    }

    ota_ctx[driver_index] = NEW_NOTHROW SecureCmdOTACtx(this, uavcan);
    if (ota_ctx[driver_index] == nullptr) {
        goto alloc_failed;
    }

    dronecan_done_init |= driver_mask;
    return;

alloc_failed:
    dronecan_init_failed |= driver_mask;
    GCS_SEND_TEXT(MAV_SEVERITY_NOTICE, "OpenDroneID DroneCAN alloc failed");
}

/*
  send pending DroneCAN OpenDroneID packets
 */
void AP_OpenDroneID::dronecan_send(AP_DroneCAN *uavcan)
{
    dronecan_init(uavcan);

    if (dronecan_init_failed & driver_mask) {
        return;
    }

    if (need_send_basic_id & driver_mask) {
        WITH_SEMAPHORE(_sem);
        dronecan_send_basic_id(uavcan);
        need_send_basic_id &= ~driver_mask;
    }
    if (need_send_system & driver_mask) {
        WITH_SEMAPHORE(_sem);
        dronecan_send_system(uavcan);
        need_send_system &= ~driver_mask;
    }
    if (need_send_self_id & driver_mask) {
        WITH_SEMAPHORE(_sem);
        dronecan_send_self_id(uavcan);
        need_send_self_id &= ~driver_mask;
    }
    if (need_send_operator_id & driver_mask) {
        WITH_SEMAPHORE(_sem);
        dronecan_send_operator_id(uavcan);
        need_send_operator_id &= ~driver_mask;
    }
    if (need_send_location & driver_mask) {
        WITH_SEMAPHORE(_sem);
        dronecan_send_location(uavcan);
        need_send_location &= ~driver_mask;
    }
    if (need_send_auth_challenge & driver_mask) {
        WITH_SEMAPHORE(_sem);
        dronecan_send_auth_challenge(uavcan);
        need_send_auth_challenge &= ~driver_mask;
    }
    if (need_send_generate_key & driver_mask) {
        WITH_SEMAPHORE(_sem);
        dronecan_send_generate_key(uavcan);
        need_send_generate_key &= ~driver_mask;
    }
    if (need_send_ota_chunk & driver_mask) {
        WITH_SEMAPHORE(_sem);
        dronecan_send_ota_chunk(uavcan);
        need_send_ota_chunk &= ~driver_mask;
    }
}

#define ODID_COPY(name) msg.name = pkt.name
#define ODID_COPY_STR(name) do { msg.name.len = strncpy_noterm((char*)msg.name.data, (const char*)pkt.name, sizeof(msg.name.data)); } while(0)


void AP_OpenDroneID::dronecan_send_auth_challenge(AP_DroneCAN *uavcan)
{
    const uint8_t driver_index = uavcan->get_driver_index();
    if (auth_ctx[driver_index] == nullptr) {
        return;
    }
    hal.util->get_random_vals(_auth_nonce, sizeof(_auth_nonce));
    _auth_challenge_sent_ms = AP_HAL::millis();

    dronecan_remoteid_SecureCommandRequest req {};
    req.sequence = _auth_challenge_sent_ms;
    req.operation = DRONECAN_REMOTEID_SECURECOMMAND_REQUEST_SECURE_COMMAND_AUTH_CHALLENGE;
    req.sig_length = 0;
    req.data.len = sizeof(_auth_nonce);
    memcpy(req.data.data, _auth_nonce, sizeof(_auth_nonce));

    auth_ctx[driver_index]->client.request(_pending_auth_node_id, req);
}

void AP_OpenDroneID::dronecan_send_generate_key(AP_DroneCAN *uavcan)
{
    const uint8_t driver_index = uavcan->get_driver_index();
    if (keygen_ctx[driver_index] == nullptr) {
        return;
    }
    dronecan_remoteid_SecureCommandRequest req {};
    req.sequence = AP_HAL::millis();
    req.operation = DRONECAN_REMOTEID_SECURECOMMAND_REQUEST_SECURE_COMMAND_GENERATE_RID_KEY;
    req.sig_length = 0;
    req.data.len = 0;
    keygen_ctx[driver_index]->client.request(_pending_auth_node_id, req);
}

void AP_OpenDroneID::dronecan_send_ota_chunk(AP_DroneCAN *uavcan)
{
    const uint8_t driver_index = uavcan->get_driver_index();
    if (ota_ctx[driver_index] == nullptr) {
        return;
    }

    dronecan_remoteid_SecureCommandRequest req {};
    req.sequence = AP_HAL::millis();
    req.operation = DRONECAN_REMOTEID_SECURECOMMAND_REQUEST_SECURE_COMMAND_OTA_CHUNK;
    req.sig_length = 0;
    // pack: flags(1) + offset(4 LE) + firmware bytes
    req.data.data[0] = _ota_chunk.flags;
    memcpy(&req.data.data[1], &_ota_chunk.offset, sizeof(_ota_chunk.offset));
    memcpy(&req.data.data[5], _ota_chunk.data, _ota_chunk.len);
    req.data.len = 5 + _ota_chunk.len;
    const uint8_t node_id = _rid_authenticated ? flying_allowed_device_node_id : _pending_auth_node_id;
    ota_ctx[driver_index]->client.request(node_id, req);
#if AP_CHECK_FIRMWARE_ENABLED && HAL_GCS_ENABLED
    if (_ota_chunk.flags & 0x02) {  // FLAG_LAST dispatched — next ACK carries the real validation result
        AP_CheckFirmware::ota_state = AP_CheckFirmware::OTAState::LAST_PENDING;
    }
#endif
}

void AP_OpenDroneID::set_auth_response(uint8_t node_id, const uint8_t *sig, uint8_t sig_len)
{
    if (sig_len < 64) {
        return;
    }
    uint8_t nonce_copy[32];
    {
        WITH_SEMAPHORE(_sem);
        memcpy(nonce_copy, _auth_nonce, sizeof(nonce_copy));
    }

    // RID-specific key takes priority over firmware signing keys
    uint8_t rid_pk[32];
    if (get_rid_public_key(rid_pk)) {
        if (crypto_check(sig, rid_pk, nonce_copy, sizeof(nonce_copy)) == 0) {
            WITH_SEMAPHORE(_sem);
            _rid_authenticated = true;
            flying_allowed_device_node_id = node_id;
            GCS_SEND_TEXT(MAV_SEVERITY_INFO, "FLDSMDFR: module ready (node %u)", node_id);
        } else {
            GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "FLDSMDFR: authentication failed (node %u)", node_id);
        }
        return;
    }

#if AP_SIGNED_FIRMWARE
    const struct ap_secure_data *sec_data = AP_CheckFirmware::find_public_keys();
    if (sec_data == nullptr || AP_CheckFirmware::all_zero_keys(sec_data)) {
        WITH_SEMAPHORE(_sem);
        _rid_authenticated = true;
        flying_allowed_device_node_id = node_id;
        return;
    }
    for (const auto &pk : sec_data->public_key) {
        if (crypto_check(sig, pk.key, nonce_copy, sizeof(nonce_copy)) == 0) {
            WITH_SEMAPHORE(_sem);
            _rid_authenticated = true;
            flying_allowed_device_node_id = node_id;
            GCS_SEND_TEXT(MAV_SEVERITY_INFO, "FLDSMDFR: module ready (node %u)", node_id);
            return;
        }
    }
    GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "FLDSMDFR: authentication failed (node %u)", node_id);
#else
    // ponytail: no public keys on unsigned build, accept any RID
    WITH_SEMAPHORE(_sem);
    _rid_authenticated = true;
    flying_allowed_device_node_id = node_id;
#endif
}

void AP_OpenDroneID::dronecan_send_location(AP_DroneCAN *uavcan)
{
    dronecan_remoteid_Location msg {};
    const auto &pkt = pkt_location;
    ODID_COPY_STR(id_or_mac);
    ODID_COPY(status);
    ODID_COPY(direction);
    ODID_COPY(speed_horizontal);
    ODID_COPY(speed_vertical);
    ODID_COPY(latitude);
    ODID_COPY(longitude);
    ODID_COPY(altitude_barometric);
    ODID_COPY(altitude_geodetic);
    ODID_COPY(height_reference);
    ODID_COPY(height);
    ODID_COPY(horizontal_accuracy);
    ODID_COPY(vertical_accuracy);
    ODID_COPY(barometer_accuracy);
    ODID_COPY(speed_accuracy);
    ODID_COPY(timestamp);
    ODID_COPY(timestamp_accuracy);
    dc_location[uavcan->get_driver_index()]->broadcast(msg);
}

void AP_OpenDroneID::dronecan_send_basic_id(AP_DroneCAN *uavcan)
{
    dronecan_remoteid_BasicID msg {};
    const auto &pkt = pkt_basic_id;
    ODID_COPY_STR(id_or_mac);
    ODID_COPY(id_type);
    ODID_COPY(ua_type);
    ODID_COPY_STR(uas_id);
    dc_basic_id[uavcan->get_driver_index()]->broadcast(msg);
}

void AP_OpenDroneID::dronecan_send_system(AP_DroneCAN *uavcan)
{
    dronecan_remoteid_System msg {};
    const auto &pkt = pkt_system;
    ODID_COPY_STR(id_or_mac);
    ODID_COPY(operator_location_type);
    ODID_COPY(classification_type);
    ODID_COPY(operator_latitude);
    ODID_COPY(operator_longitude);
    ODID_COPY(area_count);
    ODID_COPY(area_radius);
    ODID_COPY(area_ceiling);
    ODID_COPY(area_floor);
    ODID_COPY(category_eu);
    ODID_COPY(class_eu);
    ODID_COPY(operator_altitude_geo);
    ODID_COPY(timestamp);
    dc_system[uavcan->get_driver_index()]->broadcast(msg);
}

void AP_OpenDroneID::dronecan_send_self_id(AP_DroneCAN *uavcan)
{
    dronecan_remoteid_SelfID msg {};
    const auto &pkt = pkt_self_id;
    ODID_COPY_STR(id_or_mac);
    ODID_COPY(description_type);
    ODID_COPY_STR(description);
    dc_self_id[uavcan->get_driver_index()]->broadcast(msg);
}

void AP_OpenDroneID::dronecan_send_operator_id(AP_DroneCAN *uavcan)
{
    dronecan_remoteid_OperatorID msg {};
    const auto &pkt = pkt_operator_id;
    ODID_COPY_STR(id_or_mac);
    ODID_COPY(operator_id_type);
    ODID_COPY_STR(operator_id);
    dc_operator_id[uavcan->get_driver_index()]->broadcast(msg);
}

/*
  handle Status message from DroneCAN
 */
static void handle_arm_status(AP_DroneCAN *ap_dronecan, const CanardRxTransfer &transfer, const dronecan_aurelia_remoteid_Status &msg)
{
    mavlink_aurelia_odid_status_t status {};
    status.status = msg.status;
    strncpy_noterm((char*)status.error, (const char*)msg.error.data, sizeof(status.error));
    gcs().send_to_active_channels(MAVLINK_MSG_ID_AURELIA_ODID_STATUS, (const char *)&status);
    AP::opendroneid().set_arm_status(status, transfer.source_node_id, ap_dronecan->get_driver_index());
}

void AP_OpenDroneID::set_arm_status(mavlink_aurelia_odid_status_t &status, uint8_t node_id, uint8_t driver_index)
{
    last_arm_status_ms = AP_HAL::millis();
    if (_rid_authenticated && flying_allowed_device_node_id == node_id) {
        WITH_SEMAPHORE(_sem);
        arm_status = status;
        return;
    }
    if (!_rid_authenticated) {
        WITH_SEMAPHORE(_sem);
        _pending_auth_node_id = node_id;
        need_send_auth_challenge |= (1U << driver_index);
    }
}

#endif // HAL_ENABLE_DRONECAN_DRIVERS
#endif // AP_OPENDRONEID_ENABLED
