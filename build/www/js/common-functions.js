function create_header(msgType, reqId, bodylength) {
    var header = new proto.priscilla_common_api.Header();
    header.setMessageType(msgType);
    header.setRequestId(reqId);
    header.setBodyLength(bodylength);

    return header;
}

function get_available_devices() {
    var msg = new proto.priscilla_satprobe_api.get_available_devices_message();
    msg.setHeader(create_header(proto.priscilla_common_api.MessageType.PRISCILLA_GET_AVAILABLE_DEVICES, $('#header_request_id').val(), $('#header_body_length').val()));

    var bin = msg.serializeBinary();
    ws_command.send(bin);
}

function get_system_configuration() {
    var msg = new proto.priscilla_satprobe_api.get_system_configuration_message();
    msg.setHeader(create_header(proto.priscilla_common_api.MessageType.PRISCILLA_GET_SYSTEM_CONFIGURATION, $('#header_request_id').val(), $('#header_body_length').val()));

    var bin = msg.serializeBinary();
    ws_command.send(bin);
}

function get_carriers_configuration() {
    var msg = new proto.priscilla_satprobe_api.get_carriers_configuration_message();
    msg.setHeader(create_header(proto.priscilla_common_api.MessageType.PRISCILLA_GET_CARRIERS_CONFIGURATION, $('#header_request_id').val(), $('#header_body_length').val()));

    var bin = msg.serializeBinary();
    ws_command.send(bin);
}

function get_network_type_str(network_type) {
    switch (parseInt(network_type)) {
        case proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_FL:
            return "Linkstar FL";
        case proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_RL:
            return "Linkstar RL";
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_FL:
            return "iNFINITI FL";
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_RL:
            return "iNFINITI RL";
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_FL:
            return "Evolution FL";
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_RL:
            return "Evolution RL";
        case proto.priscilla_common_api.SystemType.PRISCILLA_DVB_RCS_RL:
            return "DVB-RCS RL";
        case undefined:
            return "N.A.";
        default:
            return "Unknown";
    }
}

function get_network_type_no(network_type) {
    switch (network_type) {
        case "Linkstar FL":
            return proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_FL;
        case "Linkstar RL":
            return proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_RL;
        case "iNFINITI FL":
            return proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_FL;
        case "iNFINITI RL":
            return proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_RL;
        case "Evolution FL":
            return proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_FL;
        case "Evolution RL":
            return proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_RL;
        case "DVB-RCS RL":
            return proto.priscilla_common_api.SystemType.PRISCILLA_DVB_RCS_RL;
        default:
            return 0;
    }
}

function get_modulation_str(modulation) {
    switch (parseInt(modulation)) {
        case proto.priscilla_common_api.ModulationType.PRISCILLA_MODULATION_QPSK:
            return "QPSK";
        case proto.priscilla_common_api.ModulationType.PRISCILLA_MODULATION_EIGHT_PSK:
            return "8PSK";
        case undefined:
            return "N.A.";
    }
}

function get_modulation_no(modulation) {
    switch (modulation) {
        case "QPSK":
            return proto.priscilla_common_api.ModulationType.PRISCILLA_MODULATION_QPSK;
        case "8PSK":
            return proto.priscilla_common_api.ModulationType.PRISCILLA_MODULATION_EIGHT_PSK;
        default:
            return 0;
    }
}

function get_demodulator_type_str(modulation) {
    switch (parseInt(modulation)) {
        case proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_TC1:
            return "TC1";
        case proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_SENCORE:
            return "Sencore";
            case proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_NEWTEC:
            return "Newtec";
            case proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_PSSR:
            return "PSSR";            
        case proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_NOT_USED:
        case undefined:
            return "N.A.";
    }
}

function get_demodulator_type_no(type) {
    switch (type) {
        case "TC1":
            return proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_TC1;
        case "Sencore":
            return proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_SENCORE;
        case "Newtec":
            return proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_NEWTEC;
        case "PSSR":
            return proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_PSSR;
        default:
            return proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_NOT_USED;
    }
}

function check_ip_address(ip) {
    var x = ip.split("."), x1, x2, x3, x4;

    if (x.length == 4) {
        if (x[0].trim() == "" || x[1].trim() == "" || x[2].trim() == "" || x[3].trim() == "") {
            return false;
        }

        x1 = Number(x[0]);
        x5 = Number(x[4]);
        x6 = Number(x[5]);
        x2 = Number(x[1]);
        x3 = Number(x[2]);
        x4 = Number(x[3]);

        if (isNaN(x1) || isNaN(x2) || isNaN(x3) || isNaN(x4)) {
            return false;
        }

        if ((x1 >= 0 && x1 <= 255) && (x2 >= 0 && x2 <= 255) && (x3 >= 0 && x3 <= 255) && (x4 >= 0 && x4 <= 255)) {
            return true;
        }
    }
    return false;
}

function check_mac_address(val) {
    var x = val.split(":"), x1, x2, x3, x4;

    if (x.length == 6) {
        if (x[0].trim() == "" || x[1].trim() == "" || x[2].trim() == "" || x[3].trim() == "" || x[4].trim() == "" || x[5].trim() == "") {
            return false;
        }

        x1 = parseInt(x[0], 16);
        x2 = parseInt(x[1], 16);
        x3 = parseInt(x[2], 16);
        x4 = parseInt(x[3], 16);
        x5 = parseInt(x[4], 16);
        x6 = parseInt(x[5], 16);

        if (isNaN(x1) || isNaN(x2) || isNaN(x3) || isNaN(x4) || isNaN(x5) || isNaN(x6)) {
            return false;
        }

        if ((x1 >= 0 && x1 <= 255) && (x2 >= 0 && x2 <= 255) && (x3 >= 0 && x3 <= 255) && (x4 >= 0 && x4 <= 255) && (x5 >= 0 && x5 <= 255) && (x6 >= 0 && x6 <= 255)) {
            return true;
        }
    }
    return false;
}

function clear_table(table) {
    $('#'+table+' tbody').empty();
}
