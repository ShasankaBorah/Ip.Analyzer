// Declare global variables here
var ws_command;
var ws_messages;

var g_capture_mode;
var g_system_configuration;
var g_carrier_configuration;

var devices = [];

var FECStringToValueMap = new Object();

// Linkstar FL
FECStringToValueMap["Auto"] = 0.0;

// Linkstar RL
FECStringToValueMap["0.667"] = (2.0 / 3.0);
FECStringToValueMap["0.857"] = (6.0 / 7.0);

// iNFINITI FL
FECStringToValueMap["0.495"] = ((3.0 / 4.0) * (26.0 / 32.0) * (26.0 / 32.0));
FECStringToValueMap["0.660"] = ((26.0 / 32.0) * (26.0 / 32.0));
FECStringToValueMap["0.793"] = ((57.0 / 64.0) * (57.0 / 64.0));
FECStringToValueMap["0.879"] = ((120.0 / 128.0) * (120.0 / 128.0));

// iNFINITI RL
//FECStringToValueMap.put(".660", ((26.0/32.0)*(26.0/32.0))); // Already added
//FECStringToValueMap.put(".793", ((57/64)*(57/64))); // Already added

// Evolution FL
//        FECStringToValueMap.put("Auto", 0.0); // Already added

// Evolution RL
FECStringToValueMap["0.500"] = (1.0 / 2.0);
//        FECStringToValueMap.put(".667", (2.0/3.0)); // Already added
FECStringToValueMap["0.750"] = (3.0 / 4.0);
FECStringToValueMap["0.800"] = (4.0 / 5.0);
//        FECStringToValueMap.put("6/7", (6.0/7.0)); // Already added

// Linkway S2 RL
FECStringToValueMap["0.333"] = (1.0 / 3.0);
//        FECStringToValueMap.put(".5", (1.0/2.0)); // Already added
//        FECStringToValueMap.put(".667", (2.0/3.0)); // Already added
//        FECStringToValueMap.put(".75", (3.0/4.0)); // Already added
//        FECStringToValueMap.put(".8", (4.0/5.0)); // Already added
//        FECStringToValueMap.put("6/7", (6.0/7.0)); // Already added

$(document).ready(function () {
    // Initialise GUI
    /*var select_pssr_config_clock_ref = $('#pssr_config_clock_ref_test');
    select_pssr_config_clock_ref.append('<option value=' + proto.priscilla_satprobe_api.ClockReference.CLOCK_INTERNAL + '>' + string_of_enum(proto.priscilla_satprobe_api.ClockReference, proto.priscilla_satprobe_api.ClockReference.CLOCK_INTERNAL) + '</option>');
    select_pssr_config_clock_ref.append('<option value=' + proto.priscilla_satprobe_api.ClockReference.CLOCK_EXTERNAL + '>' + string_of_enum(proto.priscilla_satprobe_api.ClockReference, proto.priscilla_satprobe_api.ClockReference.CLOCK_EXTERNAL) + '</option>');*/

    var div_select = $('#carrier_config_source_rf_band');
    div_select.append('<option value=' + proto.priscilla_common_api.RFBand.PRISCILLA_RFBAND_C_BAND + '>C Band</option>');
    div_select.append('<option value=' + proto.priscilla_common_api.RFBand.PRISCILLA_RFBAND_KU_BAND + '>Ku band</option>');
    div_select.append('<option value=' + proto.priscilla_common_api.RFBand.PRISCILLA_RFBAND_KA_BAND + '>Ka band</option>');

    div_select = $('#carrier_config_fl_based_system_type');
    div_select.append('<option value=' + proto.priscilla_common_api.SystemType.PRISCILLA_DVB_RCS_FL + '>DVB-RCS</option>');
    div_select.append('<option value=' + proto.priscilla_common_api.SystemType.PRISCILLA_GILAT_SKY_EDGE_2 + '>Gilat SkyEdge II</option>');
    
    $('select').material_select();

    // Add dummy devices
    var device = {};
    device.is_enabled = true;
    device.type = proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_TC1;
    device.name = "TC1";
    devices.push(device);

    device = {};
    device.is_enabled = true;
    device.type = proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_PSSR;
    device.name = "PSSR";
    devices.push(device);

    initialise_carrier_fns();


    var host = window.location.host;
    ws_messages = new WebSocket("ws://" + host + "/ws/message");
    ws_messages.binaryType = 'arraybuffer';
    ws_messages.onmessage = function (evt) {
        //parse_messages(evt.data);
    };

    ws_command = new WebSocket("ws://" + host + "/ws/command");
    ws_command.binaryType = 'arraybuffer';
    ws_command.onmessage = function (evt) {
        parse_command_reply(evt.data);
    };
    ws_command.onopen = function (evt) {
        get_available_devices();
        get_system_configuration();
        get_carriers_configuration();
    }

    g_system_configuration = new proto.priscilla_satprobe_api.SystemConfiguration();
    g_carrier_configuration = new proto.priscilla_satprobe_api.CarriersConfiguration();


    /*var host = window.location.host;
    var ws_msg = new WebSocket("ws://" + host + "/ws/message");
    ws_msg.onmessage = function (evt) {
        var received_msg = evt.data;
        console.log("Message is received: " + received_msg);

        if (received_msg == "settings_saved") {
            Materialize.toast('Settings saved successfully.', 2000);
        }
    };
    ws_msg.onclose = function () {
        // websocket is closed.
        console.log("Message channel is closed...");
    };

    ws_command = new WebSocket("ws://" + host + "/ws/command");
    ws_command.onopen = function () {
        // Web Socket is connected, ask for devices and configuration
        ws_command.send("get_ethernet_devices");
        ws_command.send("get_configuration");
    };
    ws_command.onmessage = function (evt) {
        var obj = JSON.parse(evt.data);

        if (obj.ethernet_devices) {
            var ip_pkts_fwd_interface = document.getElementById('ip_pkts_fwd_interface');
            var controller_ip_address = document.getElementById('controller_ip_address');
            ip_pkts_fwd_interface.options.length = 0;
            controller_ip_address.options.length = 0;
            for (var i = 0; i < obj.ethernet_devices.length; i++) {
                var name = obj.ethernet_devices[i];
                var opt = document.createElement('option');
                opt.value = name;
                opt.innerHTML = name;
                ip_pkts_fwd_interface.appendChild(opt);
                opt = document.createElement('option');
                opt.value = name;
                opt.innerHTML = name;
                controller_ip_address.appendChild(opt);
            }

            $('select').material_select();

        } else if (obj.configuration) {
            devices = obj.configuration.devices;

            $('#table_idd_devices tbody').empty();
            $('#table_tc1_devices tbody').empty();
            $('#table_pssr_devices tbody').empty();
            $('#table_carriers tbody').empty();
            $('#table_decoders tbody').empty();

            for (var i = 0; i < devices.length; ++i) {
                device = devices[i];

                // Store the enabled device names
                if (device.type == "IDD") {
                    add_idd_device(device.is_enabled,
                        device.name,
                        device.serial_no,
                        device.ip_address,
                        (device.frequency),
                        (device.sampling_rate),
                        device.gain,
                        device.clock_ref,
                        device.process_count);

                    // Decoders
                    for (var j = 0; j < device.decoders.length; ++j) {
                        decoder = device.decoders[j];

                        add_decoder(decoder.is_enabled,
                            device.name,
                            decoder.ip_address,
                            decoder.username,
                            decoder.password);
                    }
                } else if (device.type == "TC1") {
                    add_tc1_device(device.is_enabled,
                        device.name,
                        device.local_ip_address,
                        device.trf_ip_address,
                        device.mgmt_ip_address);
                } else if (device.type == "PSSR") {
                    add_pssr_device(device.is_enabled,
                        device.name,
                        device.serial_no,
                        (device.frequency),
                        (device.sampling_rate),
                        device.gain,
                        device.clock_ref,
                        device.process_count);

                    // Decoders
                    for (var j = 0; j < device.decoders.length; ++j) {
                        decoder = device.decoders[j];

                        add_decoder(decoder.is_enabled,
                            device.name,
                            decoder.ip_address,
                            decoder.username,
                            decoder.password);
                    }
                }

                // Carriers
                if (device.carriers) {
                    for (var j = 0; j < device.carriers.length; ++j) {
                        carrier = device.carriers[j];

                        add_carrier(carrier.is_enabled,
                            device.name,
                            device.type,
                            get_network_type_str(carrier.network_type),
                            carrier.network_id,
                            numeral(carrier.frequency).divide(1e6),
                            carrier.frame_format == "0" || carrier.frame_format == undefined ? "N.A." : carrier.frame_format,
                            get_modulation_str(carrier.modulation),
                            carrier.symbol_rate == "0" || carrier.symbol_rate == undefined ? "N.A." : numeral(carrier.symbol_rate).divide(1e3).formatNumber(3),
                            carrier.code_rate == "0" || carrier.code_rate == undefined ? "N.A." : numeral(carrier.code_rate).formatNumber(3),
                            carrier.is_spectrum_inverted == undefined ? "false" : carrier.is_spectrum_inverted,
                            carrier.block_size == "0" || carrier.block_size == undefined ? "N.A." : carrier.block_size);
                    }
                }
            }

            // Controller settings
            var controller_ip_address = document.getElementById('controller_ip_address');
            for (var i = 0; i < controller_ip_address.options.length; i++) {
                if (controller_ip_address.options[i].value.indexOf(obj.configuration.controller.ip_address) > -1) {
                    controller_ip_address.options[i].selected = true;
                    break;
                }
            }
            document.getElementById('controller_control_port').value = obj.configuration.controller.control_port;
            document.getElementById('controller_data_port').value = obj.configuration.controller.data_port;

            // IP Packets Forwarding and Storage
            if (obj.configuration.ip_pkts_forwarding) {
                document.getElementById('ip_pkts_fwd_enable').checked = obj.configuration.ip_pkts_forwarding.enabled == "true";

                var ip_pkts_fwd_interface = document.getElementById('ip_pkts_fwd_interface');
                for (var i = 0; i < ip_pkts_fwd_interface.options.length; i++) {
                    if (ip_pkts_fwd_interface.options[i].value.indexOf(obj.configuration.ip_pkts_forwarding.interface_name) > -1) {
                        ip_pkts_fwd_interface.options[i].selected = true;
                        break;
                    }
                }

                if (obj.configuration.ip_pkts_storage) {
                    document.getElementById('ip_pkts_storage_enable').checked = obj.configuration.ip_pkts_storage.enabled == "true";
                    document.getElementById('ip_pkts_storage_path').value = obj.configuration.ip_pkts_storage.path;
                    document.getElementById('ip_pkts_storage_split_value').value = obj.configuration.ip_pkts_storage.split_value;
                    // Size(MB) = 0, Count = 1, secs = 2, min = 3, hr = 4
                    document.getElementById('ip_pkts_storage_split_type').options[parseInt(obj.configuration.ip_pkts_storage.split_type)].selected = true;
                }

                if (obj.configuration.network_id_to_mac_map) {
                    for (var i = 0; i < obj.configuration.network_id_to_mac_map.length; ++i) {
                        var item = obj.configuration.network_id_to_mac_map[i];
                        var row_count = $('#table_network_id_to_mac tbody tr').length;
                        var str = '<tr><td>' + item.network_id + '</td> \
                                       <td>' + item.src_mac_address + '</td> \
                                       <td>' + item.dst_mac_address + '</td> \
                                       <td><img src="icons/ic_mode_edit_black_18px.svg" style="cursor: pointer;" onclick="edit_network_id()"></i></td> \
                                       <td><img src="icons/ic_clear_black_18px.svg" style="cursor: pointer;" onclick="remove_network_id()"></i></td></tr>';
                        $('#table_network_id_to_mac tbody').append(str);
                    }
                }
                $('select').material_select();
            }
        }
    };
    ws_command.onclose = function () {
        // websocket is closed.
        console.log("Command channel is closed...");
    };*/
});

function get_tc1_configuration() {
    var config = new proto.priscilla_common_api.TC1Configuration();

    config.setLocalIpAddress($('#system_config_tc1_config_local_ip_address').val());
    config.setTc1IpAddress($('#system_config_tc1_config_tc1_ip_address').val());
    config.setForwardingMac($('#system_config_tc1_config_fwd_mac').val());
    config.setForwardingUdpPort($('#system_config_tc1_config_fwd_udp_port').val());

    return config;
}

function get_sencore_configuration() {
    var config = new proto.priscilla_satprobe_api.SencoreConfiguration();

    return config;
}

function get_newtec_configuration() {
    var config = new proto.priscilla_satprobe_api.NewtecConfiguration();

    return config;
}

function get_decoder_configuration() {
    var config = new proto.priscilla_satprobe_api.DecoderConfiguration();

    config.setControlIpAddress($('#system_config_decoder_config_control_ip_address').val());
    config.setControlPort($('#system_config_decoder_config_control_port').val());
    config.setDecoderIpAddress($('#system_config_decoder_config_decoder_ip_address').val());
    config.setDecoderUsername($('#system_config_decoder_config_decoder_username').val());
    config.setDecoderPassword($('#system_config_decoder_config_decoder_password').val());

    return config;
}

function get_ip_forwarding_configuration() {
    var config = new proto.priscilla_satprobe_api.IPForwardingConfiguration();

    config.setIsEnabled($('#system_config_ip_fwd_is_enabled').get(0).checked);
    config.setEthInterface($('#system_config_ip_fwd_eth_interface').val());
    config.setDelay($('#system_config_ip_fwd_delay').val());
    config.setDestinationMacAddress($('#system_config_ip_fwd_destination_mac_address').val());

    return config;
}

function get_ip_storage_configuration() {
    var config = new proto.priscilla_satprobe_api.IPStorageConfiguration();

    config.setIsEnabled($('#system_config_ip_storage_is_enabled').get(0).checked);
    config.setPath($('#system_config_ip_storage_path').val());
    config.setSplitValue($('#system_config_ip_storage_split_value').val());
    config.setSplitType($('#system_config_ip_storage_split_type').val());
    config.setDestinationMacAddress($('#system_config_ip_storage_destination_mac_address').val());

    return config;
}

function get_debug_configuration() {
    var config = new proto.priscilla_satprobe_api.DebugConfiguration();

    config.setIsEnabled($('#system_config_debug_is_enabled').get(0).checked);
    config.setTraceLevel($('#system_config_debug_trace_level').val());

    return config;
}

function set_system_configuration() {
    var msg = new proto.priscilla_satprobe_api.set_system_configuration_message();
    msg.setHeader(create_header(proto.priscilla_common_api.MessageType.PRISCILLA_SET_SYSTEM_CONFIGURATION, $('#header_request_id').val(), $('#header_body_length').val()));

    g_system_configuration.setNetworkId($('#system_config_network_id').val());

    g_system_configuration.setMasterSatprobeIpAddress($('#system_config_master_satprobe_ip_address').val());

    g_system_configuration.setDecoderConfiguration(get_decoder_configuration());
    g_system_configuration.setIpForwardingConfiguration(get_ip_forwarding_configuration());
    g_system_configuration.setIpStorageConfiguration(get_ip_storage_configuration());
    g_system_configuration.setDebugConfiguration(get_debug_configuration());

    g_system_configuration.setTc1Configuration(get_tc1_configuration());
    // g_system_configuration.setSencoreConfiguration(get_sencore_configuration());
    // g_system_configuration.setNewtecConfiguratin(get_newtec_configuration());

    g_system_configuration.setPssrConfiguration(get_pssr_configuration());

    msg.setConfiguration(g_system_configuration);

    var bin = msg.serializeBinary();
    ws_command.send(bin);

    $('#btn_set_system_config').animateCss('fadeIn');
}

function get_pssr_configuration() {
    var config = new proto.priscilla_satprobe_api.PSSRConfiguration();

    config.setCentreFrequency($('#pssr_config_center_frequency').val() * 1e6);
    config.setSamplingRate($('#pssr_config_sampling_rate').val() * 1e6);
    config.setGain($('#pssr_config_gain').val());
    config.setClockReference(val_of_enum(proto.priscilla_common_api.ClockReference, $('#pssr_config_clock_ref').val()));

    return config;
}

function validate_carrier_configuration() {
    //$('#edit_carrier_modal').find('input').removeClass('invalid');

    field = $('#carrier_config_fl_based_frequency');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }
    var val = Number(field.val());
    if (isNaN(val) || val < 950 || val > 2150) {
        field.addClass('invalid');
        return false;
    }

    return true;
}

function set_carriers_configuration() {
    if (!validate_carrier_configuration()) return;

    var msg = new proto.priscilla_satprobe_api.set_carriers_configuration_message();
    msg.setHeader(create_header(proto.priscilla_common_api.MessageType.PRISCILLA_SET_CARRIERS_CONFIGURATION, $('#header_request_id').val(), $('#header_body_length').val()));

    g_carrier_configuration.setCaptureMode(g_capture_mode);
    //update_capture_mode();
    
    g_carrier_configuration.setSourceRfBand($('#carrier_config_source_rf_band option:selected').val());    
    
    // Normal Mode
    g_carrier_configuration.clearCarriersList();
    var rows = $('#table_carriers tbody').find('tr');
    for (i = 0; i < rows.length; ++i) {
        var carrier = new proto.priscilla_common_api.CarrierBasicInformation();
        carrier.setIsEnabled(rows[i].children[0].children[0].checked);
        carrier.setDemodulatorType(get_demodulator_type_no(rows[i].children[1].innerHTML));
        carrier.setFrequency(numeral(rows[i].children[2].innerHTML).multiply(1e6).value());
        carrier.setSystemType(get_network_type_no(rows[i].children[3].innerHTML));
        carrier.setSymbolRate(rows[i].children[4].innerHTML == "-" ? 0 : numeral(rows[i].children[4].innerHTML).multiply(1e3));
        carrier.setModulation(rows[i].children[5].innerHTML == "-" ? 0 : get_modulation_no(rows[i].children[5].innerHTML));
        carrier.setInnerFec(rows[i].children[6].innerHTML == "-" ? 0 : rows[i].children[6].innerHTML);
        carrier.setBlockSize(rows[i].children[7].innerHTML == "-" ? 0 : rows[i].children[7].innerHTML);
        carrier.setFrameFormat(rows[i].children[8].innerHTML == "-" ? 0 : rows[i].children[8].innerHTML);

        g_carrier_configuration.addCarriers(carrier);
    }

    // FL Based Mode
    var fl_based_config = new proto.priscilla_satprobe_api.FLBasedModeConfiguration();
    fl_based_config.setSystemType($('#carrier_config_fl_based_system_type option:selected').val());
    fl_based_config.setFlFrequency(numeral($('#carrier_config_fl_based_frequency').val()).multiply(1e6));
    
    fl_based_config.setLnbConvFrequency(numeral($('#carrier_config_lnb_conv_frequency').val()).multiply(1e6));
    fl_based_config.setSatelliteConvFrequency(numeral($('#carrier_config_satellite_conv_frequency').val()).multiply(1e6));

    var rows = $('#table_rl_carriers_from_fl tbody').find('tr');
    for (i = 0; i < rows.length; ++i) {
        var carrier = new proto.priscilla_common_api.CarrierBasicInformation();
        carrier.setIsEnabled(rows[i].children[0].children[0].checked);
        carrier.setFrequency(numeral(rows[i].children[1].innerHTML).multiply(1e6).value());
        carrier.setSystemType(get_network_type_no(rows[i].children[2].innerHTML));
        carrier.setSymbolRate(numeral(rows[i].children[3].innerHTML).multiply(1e3));
        carrier.setModulation(get_modulation_no(rows[i].children[4].innerHTML));
        carrier.setInnerFec(rows[i].children[5].innerHTML);

        fl_based_config.addRlCarriers(carrier);
    }

    g_carrier_configuration.setFlBasedModeConfiguration(fl_based_config);

    msg.setConfiguration(g_carrier_configuration);

    var bin = msg.serializeBinary();
    ws_command.send(bin);

    $('#btn_set_carriers_config').animateCss('fadeIn');
}

function parse_command_reply(data) {
    if (data instanceof ArrayBuffer) {
        var array = new Uint8Array(data);
        try {
            var getMessageHeader = proto.priscilla_common_api.get_message_header.deserializeBinary(array);
        } catch (e) {
            console.log(e.message); // "missing ; before statement"
            console.log(array); // "SyntaxError"
            $('#header_message_type').val('Unknown Message');
            return;
        }

        $('#header_message_type').val(string_of_enum(proto.priscilla_common_api.MessageType, getMessageHeader.getHeader().getMessageType()));
        $('#header_request_id').val(getMessageHeader.getHeader().getRequestId());
        $('#header_body_length').val(getMessageHeader.getHeader().getBodyLength());
        $('#return_code').val(string_of_enum(proto.priscilla_common_api.ReturnCode, getMessageHeader.getReturnMessage().getCode()));
        $('#return_message').val(getMessageHeader.getReturnMessage().getMessage());
        $('#msg_timestamp').val(moment().format('MMMM Do YYYY, h:mm:ss a'));

        switch (getMessageHeader.getHeader().getMessageType()) {
            case proto.priscilla_common_api.MessageType.PRISCILLA_GET_AVAILABLE_DEVICES:
                var msg = proto.priscilla_satprobe_api.get_available_devices_message.deserializeBinary(array);
                if (msg.getEthernetDevicesList()) {
                    var div_select = $('#system_config_tc1_config_local_ip_address');
                    if (msg.getEthernetDevicesList().length > 0) {
                        for (i = 0; i < msg.getEthernetDevicesList().length; i++) {
                            div_select.append('<option value=' + msg.getEthernetDevicesList()[i].getIpAddress() + '>'+msg.getEthernetDevicesList()[i].getIpAddress()+'</option>');
                        }
                    } else {
                        div_select.append('<option value="">No Interface</option>');
                    }

                    $('select').material_select();
                }
                if (msg.getTc1DevicesList()) {}
                if (msg.getPssrDevicesList()) {}
                break;
            case proto.priscilla_common_api.MessageType.PRISCILLA_GET_SYSTEM_CONFIGURATION:
                var msg = proto.priscilla_satprobe_api.get_system_configuration_message.deserializeBinary(array);
                var config = msg.getConfiguration();

                $('#div_system_config input').val(' ');

                $('#system_config_network_id').val(config.getNetworkId());

                $('#system_config_master_satprobe_ip_address').val(config.getMasterSatprobeIpAddress());

                if (config.getDecoderConfiguration()) {
                    $('#system_config_decoder_config_control_ip_address').val(config.getDecoderConfiguration().getControlIpAddress());
                    $('#system_config_decoder_config_control_port').val(config.getDecoderConfiguration().getControlPort());

                    $('#system_config_decoder_config_decoder_ip_address').val(config.getDecoderConfiguration().getDecoderIpAddress());
                    $('#system_config_decoder_config_decoder_username').val(config.getDecoderConfiguration().getDecoderUsername());
                    $('#system_config_decoder_config_decoder_password').val(config.getDecoderConfiguration().getDecoderPassword());
                }

                if (config.getIpForwardingConfiguration()) {
                    $('#system_config_ip_fwd_is_enabled').get(0).checked = config.getIpForwardingConfiguration().getIsEnabled();
                    $('#system_config_ip_fwd_eth_interface').val(config.getIpForwardingConfiguration().getEthInterface());
                    $('#system_config_ip_fwd_delay').val(config.getIpForwardingConfiguration().getDelay());
                    $('#system_config_ip_fwd_destination_mac_address').val(config.getIpForwardingConfiguration().getDestinationMacAddress());
                }

                if (config.getIpStorageConfiguration()) {
                    $('#system_config_ip_storage_is_enabled').get(0).checked = config.getIpStorageConfiguration().getIsEnabled();
                    $('#system_config_ip_storage_path').val(config.getIpStorageConfiguration().getPath());
                    $('#system_config_ip_storage_split_value').val(config.getIpStorageConfiguration().getSplitValue());
                    $('#system_config_ip_storage_split_type').val(config.getIpStorageConfiguration().getSplitType());
                    $('#system_config_ip_storage_destination_mac_address').val(config.getIpStorageConfiguration().getDestinationMacAddress());
                }

                if (config.getDebugConfiguration()) {
                    $('#system_config_debug_is_enabled').get(0).checked = config.getDebugConfiguration().getIsEnabled();
                    $('#system_config_debug_trace_level').val(config.getDebugConfiguration().getTraceLevel());
                }

                if (config.getTc1Configuration()) {
                    $('#system_config_tc1_config_local_ip_address').val(config.getTc1Configuration().getLocalIpAddress());
                    $('#system_config_tc1_config_tc1_ip_address').val(config.getTc1Configuration().getTc1IpAddress());
                    $('#system_config_tc1_config_fwd_mac').val(config.getTc1Configuration().getForwardingMac());
                    $('#system_config_tc1_config_fwd_udp_port').val(config.getTc1Configuration().getForwardingUdpPort());
                }

                if (config.getPssrConfiguration()) {
                    $('#pssr_config_center_frequency').val(numeral(config.getPssrConfiguration().getCentreFrequency()).divide(1e6).toFixed(3));
                    $('#pssr_config_sampling_rate').val(numeral(config.getPssrConfiguration().getSamplingRate()).divide(1e6).toFixed(3));
                    $('#pssr_config_gain').val(config.getPssrConfiguration().getGain());
                    $('#pssr_config_clock_ref').val(string_of_enum(proto.priscilla_common_api.ClockReference, config.getPssrConfiguration().getClockReference()));
                }
                break;
            case proto.priscilla_common_api.MessageType.PRISCILLA_SET_SYSTEM_CONFIGURATION:
                break;
            case proto.priscilla_common_api.MessageType.PRISCILLA_GET_CARRIERS_CONFIGURATION:
                var msg = proto.priscilla_satprobe_api.get_carriers_configuration_message.deserializeBinary(array);
                var config = msg.getConfiguration();

                g_capture_mode = config.getCaptureMode();
                update_capture_mode();
                
                select_option('carrier_config_source_rf_band', config.getSourceRfBand());
                
                clear_table('table_carriers');
                if (config && config.getCarriersList() && config.getCarriersList() instanceof Array) {
                    for (i = 0; i < config.getCarriersList().length; i++) {
                        var carrier = config.getCarriersList()[i];
                        add_carrier(
                            carrier.getIsEnabled(),
                            carrier.getDemodulatorType(),
                            carrier.getFrequency(),
                            carrier.getSystemType(),
                            carrier.getSymbolRate(),
                            carrier.getModulation(),
                            carrier.getInnerFec(),
                            carrier.getBlockSize(),
                            carrier.getFrameFormat());
                    }
                }

                if (config.hasFlBasedModeConfiguration()) {
                    select_option('carrier_config_fl_based_system_type', config.getFlBasedModeConfiguration().getSystemType());
                    $('#carrier_config_fl_based_frequency').val(numeral(config.getFlBasedModeConfiguration().getFlFrequency()).divide(1e6).toFixed(3));

                    $('#carrier_config_lnb_conv_frequency').val(numeral(config.getFlBasedModeConfiguration().getLnbConvFrequency()).divide(1e6).toFixed(3));
                    $('#carrier_config_satellite_conv_frequency').val(numeral(config.getFlBasedModeConfiguration().getSatelliteConvFrequency()).divide(1e6).toFixed(3));
                    
                    clear_table('table_rl_carriers_from_fl');
                    if (config.getFlBasedModeConfiguration().getRlCarriersList() && config.getFlBasedModeConfiguration().getRlCarriersList() instanceof Array) {
                        for (i = 0; i < config.getFlBasedModeConfiguration().getRlCarriersList().length; i++) {
                            var carrier = config.getFlBasedModeConfiguration().getRlCarriersList()[i];
                            add_fl_based_rl_carrier(
                                carrier.getIsEnabled(),
                                carrier.getFrequency(),
                                carrier.getSystemType(),
                                carrier.getSymbolRate(),
                                carrier.getModulation(),
                                carrier.getInnerFec());
                        }
                    }
                }
                break;
            case proto.priscilla_common_api.MessageType.PRISCILLA_SET_CARRIERS_CONFIGURATION:
                break;
            case proto.priscilla_common_api.MessageType.PRISCILLA_GET_FL_BASED_RL_CARRIERS:
                $('#btn_get_rl_carriers_from_fl').removeClass('disabled');
                $('#btn_get_rl_carriers_from_fl').html('Cancel');
                break;
            case proto.priscilla_common_api.MessageType.PRISCILLA_CANCEL_GET_FL_BASED_RL_CARRIERS:
                $('#btn_get_rl_carriers_from_fl').removeClass('disabled');
                $('#btn_get_rl_carriers_from_fl').html('Get RL Carriers');
                break;
            case proto.priscilla_common_api.MessageType.PRISCILLA_FL_BASED_RL_CARRIERS:
                var msg = proto.priscilla_satprobe_api.rl_carriers_from_fl_message.deserializeBinary(array);                
                
                $('#btn_get_rl_carriers_from_fl').removeClass('disabled');
                $('#btn_get_rl_carriers_from_fl').html('Get RL Carriers');
                
                clear_table('table_rl_carriers_from_fl');
                if (msg.getCarriersList() && msg.getCarriersList() instanceof Array) {
                    for (i = 0; i < msg.getCarriersList().length; i++) {
                        var carrier = msg.getCarriersList()[i];
                        add_fl_based_rl_carrier(
                            carrier.getIsEnabled(),
                            carrier.getFrequency(),
                            carrier.getSystemType(),
                            carrier.getSymbolRate(),
                            carrier.getModulation(),
                            carrier.getInnerFec());
                    }
                }
                break;
            default:
                console.log(data);
                $('#header_message_type').val('Message Type not supported: ' + getMessageHeader.getHeader().getMessageType());
        }
    } else {
        console.log(data);
        $('#header_message_type').val('Unable to parse data.');
    }
}

function add_new_tc1_device() {
    rowSelected = -1;
    $('#edit_tc1_device_modal').openModal();
}

function add_tc1_device(is_enabled, name, local_ip_address, trf_ip_address, mgmt_ip_address) {
    var row_count = $('#table_tc1_devices tbody tr').length;
    var str = '<tr><td><input type="checkbox" id="tc1_enabled_' + row_count + '" ' + (is_enabled == true || is_enabled == "true" ? 'checked="checked"' : '') + '/><label for="tc1_enabled_' + row_count + '"></label></td> \
                        <td>' + name + '</td> \
                        <td>' + local_ip_address + '</td> \
                        <td>' + trf_ip_address + '</td> \
                        <td>' + mgmt_ip_address + '</td> \
                        <td><img src="icons/ic_mode_edit_black_18px.svg" style="cursor: pointer;" onclick="edit_tc1_device()"></i></td> \
                        <td><img src="icons/ic_clear_black_18px.svg" style="cursor: pointer;" onclick="remove_tc1_device()"></i></td></tr>';
    $('#table_tc1_devices tbody').append(str);
}

function remove_tc1_device() {
    $('#table_tc1_devices tbody').find('tr').click(function () {
        $(this).remove();
    });
}

function edit_tc1_device() {
    $('#table_tc1_devices').find('tr').click(function () {
        rowSelected = $(this).index();

        var $row = $(this);

        document.getElementById('edit_tc1_device_name').value = $row.find(':nth-child(2)').text();
        document.getElementById('edit_tc1_local_ip_address').value = $row.find(':nth-child(3)').text();
        document.getElementById('edit_tc1_traffic_ip_address').value = $row.find(':nth-child(4)').text();
        document.getElementById('edit_tc1_mgmt_ip_address').value = $row.find(':nth-child(5)').text();
    });

    $('#edit_tc1_device_modal').openModal();
}

function edit_tc1_device_ok() {
    var is_valid = validate_tc1_device();
    if (!is_valid) return;

    if (rowSelected == -1) {
        add_tc1_device(true,
            document.getElementById('edit_tc1_device_name').value.trim(),
            document.getElementById('edit_tc1_local_ip_address').value.trim(),
            document.getElementById('edit_tc1_traffic_ip_address').value.trim(),
            document.getElementById('edit_tc1_mgmt_ip_address').value.trim());
        var device = {};
        device.is_enabled = true;
        device.type = "TC1";
        device.name = document.getElementById('edit_tc1_device_name').value;

        devices.push(device);

    } else {
        var selectedRow = $('#table_tc1_devices tbody').find('tr')[rowSelected];

        var old_device_name = selectedRow.children[1].innerHTML;

        selectedRow.children[1].innerHTML = document.getElementById('edit_tc1_device_name').value.trim();
        selectedRow.children[2].innerHTML = document.getElementById('edit_tc1_local_ip_address').value.trim();
        selectedRow.children[3].innerHTML = document.getElementById('edit_tc1_traffic_ip_address').value.trim();
        selectedRow.children[4].innerHTML = document.getElementById('edit_tc1_mgmt_ip_address').value.trim();

        var new_device_name = selectedRow.children[1].innerHTML;

        update_device_names(old_device_name, new_device_name);
        update_device_names_in_carriers_table(old_device_name, new_device_name);
        update_device_names_in_decoders_table(old_device_name, new_device_name);
    }

    $('#edit_tc1_device_modal').closeModal();
}

function validate_tc1_device() {
    $('#edit_tc1_device_modal').find('input').removeClass('invalid');

    var field = $('#edit_tc1_device_name');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        /*label = $("label[for='"+field.attr('id')+"']");
        label.addClass("validate");
        label.attr("data-error","Please fill Device Name.");*/
        field.addClass('invalid');
        return false;
    }

    field = $('#edit_tc1_local_ip_address');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }
    if (!check_ip_address(field.val())) {
        field.addClass('invalid');
        return;
    }

    field = $('#edit_tc1_traffic_ip_address');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }
    if (!check_ip_address(field.val())) {
        field.addClass('invalid');
        return;
    }

    field = $('#edit_tc1_mgmt_ip_address');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }
    if (!check_ip_address(field.val())) {
        field.addClass('invalid');
        return;
    }

    return true;
}

function add_idd_device(is_enabled, name, serial_no, ip_address, frequency, sampling_rate, gain, clockRef, process_count) {
    var row_count = $('#table_idd_devices tbody tr').length;
    var str = '<tr><td><input type="checkbox" id="idd_enabled_' + row_count + '" ' + (is_enabled == true || is_enabled == "true" ? 'checked="checked"' : '') + '/><label for="idd_enabled_' + row_count + '"></label></td> \
                        <td>' + name + '</td> \
                        <td>' + serial_no + '</td> \
                        <td>' + ip_address + '</td> \
                        <td>' + numeral(frequency).divide(1e6) + '</td> \
                        <td>' + numeral(sampling_rate).divide(1e6) + '</td> \
                        <td>' + gain + '</td> \
                        <td>' + clockRef + '</td> \
                        <td>' + process_count + '</td> \
                        <td><img src="icons/ic_mode_edit_black_18px.svg" style="cursor: pointer;" onclick="edit_idd_device()"></i></td> \
                        <td><img src="icons/ic_clear_black_18px.svg" style="cursor: pointer;" onclick="remove_idd_device()"></i></td></tr>';
    $('#table_idd_devices tbody').append(str);
}

function remove_idd_device() {
    $('#table_idd_devices tbody').find('tr').click(function () {
        $(this).remove();
    });
}

function edit_idd_device() {
    $('#table_idd_devices').find('tr').click(function () {
        rowSelected = $(this).index();

        var $row = $(this);

        document.getElementById('edit_idd_device_name').value = $row.find(':nth-child(2)').text();
        document.getElementById('edit_idd_device_details').value = $row.find(':nth-child(3)').text() + " (" + $row.find(':nth-child(4)').text() + ")";
        document.getElementById('edit_idd_device_frequency').value = $row.find(':nth-child(5)').text();

        var sampling_rate_select = document.getElementById('edit_idd_device_sampling_rate');
        switch ($row.find(':nth-child(6)').text()) {
            case "3.125":
                sampling_rate_select.selectedIndex = 0;
                break;
            case "6.25":
                sampling_rate_select.selectedIndex = 1;
                break;
            case "12.5":
                sampling_rate_select.selectedIndex = 2;
                break;
            case "25":
                sampling_rate_select.selectedIndex = 3;
                break;
        }

        document.getElementById('edit_idd_device_gain').value = $row.find(':nth-child(7)').text();

        var clock_ref_select = document.getElementById('edit_idd_device_clock_ref');
        switch ($row.find(':nth-child(8)').text()) {
            case "internal":
                clock_ref_select.selectedIndex = 0;
                break;
            case "external":
                clock_ref_select.selectedIndex = 1;
                break;
        }

        document.getElementById('edit_idd_device_process_count').value = $row.find(':nth-child(9)').text();

        $('select').material_select();
    });

    $('#edit_idd_modal').openModal();
}

function edit_idd_ok() {
    var is_valid = validate_idd_device();
    if (!is_valid) return;

    var selectedRow = $('#table_idd_devices tbody').find('tr')[rowSelected];

    var old_device_name = selectedRow.children[1].innerHTML;

    selectedRow.children[1].innerHTML = document.getElementById('edit_idd_device_name').value.trim();
    selectedRow.children[4].innerHTML = document.getElementById('edit_idd_device_frequency').value.trim();
    selectedRow.children[5].innerHTML = document.getElementById('edit_idd_device_sampling_rate').value;
    selectedRow.children[6].innerHTML = document.getElementById('edit_idd_device_gain').value.trim();
    selectedRow.children[7].innerHTML = document.getElementById('edit_idd_device_clock_ref').value;
    selectedRow.children[8].innerHTML = document.getElementById('edit_idd_device_process_count').value.trim();

    var new_device_name = selectedRow.children[1].innerHTML;

    update_device_names(old_device_name, new_device_name);
    update_device_names_in_carriers_table(old_device_name, new_device_name);
    update_device_names_in_decoders_table(old_device_name, new_device_name);

    $('#edit_idd_modal').closeModal();
}

function validate_idd_device() {
    $('#edit_idd_modal').find('input').removeClass('invalid');

    var device_name = $('#edit_idd_device_name');
    device_name.removeClass('invalid');
    if (device_name.val() == null || device_name.val().trim() == "") {
        device_name.addClass('invalid');
        return false;
    }

    var frequency = $('#edit_idd_device_frequency');
    frequency.removeClass('invalid');
    if (frequency.val() == null || frequency.val().trim() == "") {
        frequency.addClass('invalid');
        return false;
    }
    var freq_val = Number(frequency.val());
    if (isNaN(freq_val) || freq_val < 950 || freq_val > 2150) {
        frequency.addClass('invalid');
        return;
    }

    var gain = $('#edit_idd_device_gain');
    gain.removeClass('invalid');
    if (gain.val() == null || gain.val().trim() == "") {
        gain.addClass('invalid');
        return false;
    }
    var gain_val = Number(gain.val());
    if (isNaN(gain_val) || gain_val < 0 || gain_val > 30) {
        gain.addClass('invalid');
        return;
    }

    var process_count = $('#edit_idd_device_process_count');
    process_count.removeClass('invalid');
    if (process_count.val() == null || process_count.val().trim() == "") {
        process_count.addClass('invalid');
        return false;
    }
    var process_count_val = Number(process_count.val());
    if (isNaN(process_count_val) || process_count_val < 1 || process_count_val > 32) {
        process_count.addClass('invalid');
        return;
    }

    return true;
}

function add_pssr_device(is_enabled, name, serial_no, frequency, sampling_rate, gain, clockRef, process_count) {
    var row_count = $('#table_pssr_devices tbody tr').length;
    var str = '<tr><td><input type="checkbox" id="pssr_enabled_' + row_count + '" ' + (is_enabled == true || is_enabled == "true" ? 'checked="checked"' : '') + '/><label for="pssr_enabled_' + row_count + '"></label></td> \
                        <td>' + name + '</td> \
                        <td>' + serial_no + '</td> \
                        <td>' + numeral(frequency).divide(1e6) + '</td> \
                        <td>' + numeral(sampling_rate).divide(1e6) + '</td> \
                        <td>' + gain + '</td> \
                        <td>' + clockRef + '</td> \
                        <td>' + process_count + '</td> \
                        <td><img src="icons/ic_mode_edit_black_18px.svg" style="cursor: pointer;" onclick="edit_pssr_device()"></i></td> \
                        <td><img src="icons/ic_clear_black_18px.svg" style="cursor: pointer;" onclick="remove_pssr_device()"></i></td></tr>';
    $('#table_pssr_devices tbody').append(str);
}

function initialise_carrier_fns() {
    $('#edit_carrier_device_name').on('change', function () {
        var selected_device_value = parseInt($('#edit_carrier_device_name').val());
        var selected_device = null;

        for (var i = 0; i < devices.length; i++) {
            if (selected_device_value === devices[i].type) {
                selected_device = devices[i];
                break;
            }
        }

        if (selected_device == null) return;

        $('#edit_carrier_device_type').val(string_of_enum(proto.priscilla_common_api.DemodulatorType, selected_device.type));

        update_carrier_network_types($('#edit_carrier_network_type').val());
    });

    $('#edit_carrier_network_type').on('change', function () {
        populate_frame_format();
        populate_modulation();
        populate_symbol_rate();
        populate_code_rate();
        populate_block_size();
    });

    $('#edit_carrier_frame_format').on('change', function () {
        populate_modulation();
        populate_symbol_rate();
        populate_code_rate();
        populate_block_size();
    });

    $('#edit_carrier_modulation').on('change', function () {
        populate_symbol_rate();
        populate_code_rate();
        populate_block_size();
    });
}

function update_carrier_network_types(selected_option) {
    var network_type_select = document.getElementById('edit_carrier_network_type');
    network_type_select.options.length = 0;

    $('select').material_select('destroy');
    switch (val_of_enum(proto.priscilla_common_api.DemodulatorType, $('#edit_carrier_device_type').val())) {
        case proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_TC1:

            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_FL;
            opt.innerHTML = get_network_type_str(opt.value);
            network_type_select.appendChild(opt);

            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_FL;
            opt.innerHTML = get_network_type_str(opt.value);
            network_type_select.appendChild(opt);

            break;
        case proto.priscilla_common_api.DemodulatorType.PRISCILLA_FL_DEMOD_PSSR:
            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_RL;
            opt.innerHTML = get_network_type_str(opt.value);
            network_type_select.appendChild(opt);

            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_FL;
            opt.innerHTML = get_network_type_str(opt.value);
            network_type_select.appendChild(opt);

            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_RL;
            opt.innerHTML = get_network_type_str(opt.value);
            network_type_select.appendChild(opt);

            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_RL;
            opt.innerHTML = get_network_type_str(opt.value);
            network_type_select.appendChild(opt);

            break;
    }

    $('select').material_select();

    if (selected_option != null)
        select_option('edit_carrier_network_type', selected_option);

    populate_frame_format();
    populate_modulation();
    populate_symbol_rate();
    populate_code_rate();
    populate_block_size();
}

function populate_frame_format(i) {
    var opt;
    select = document.getElementById('edit_carrier_frame_format');

    switch (parseInt($('#edit_carrier_network_type').val())) {
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_RL:
            select.disabled = false;
            select.options.length = 0;

            opt = document.createElement('option');
            opt.value = "1";
            opt.innerHTML = "1";
            select.appendChild(opt);

            opt = document.createElement('option');
            opt.value = "2";
            opt.innerHTML = "2";
            select.appendChild(opt);

            $('select').material_select();
            break;
        default:
            select.disabled = true;
            select.options.length = 0;

            opt = document.createElement('option');
            opt.value = "0";
            opt.innerHTML = "N.A.";
            select.appendChild(opt);
    }
}

function populate_modulation() {
    var opt;
    select = document.getElementById('edit_carrier_modulation');
    var prev_val = select.value;
    $('select').material_select('destroy');
    switch (parseInt($('#edit_carrier_network_type').val())) {
        case proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_FL:
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_FL:
            select.disabled = true;
            select.options.length = 0;

            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.ModulationType.PRISCILLA_MODULATION_NOT_USED;
            opt.innerHTML = "N.A.";
            select.appendChild(opt);
            break;
        case proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_RL:
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_FL:
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_RL:
            select.disabled = false;
            select.options.length = 0;

            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.ModulationType.PRISCILLA_MODULATION_QPSK;
            opt.innerHTML = get_modulation_str(opt.value);
            select.appendChild(opt);
            break;
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_RL:
            select.disabled = false;
            select.options.length = 0;

            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.ModulationType.PRISCILLA_MODULATION_QPSK;
            opt.innerHTML = get_modulation_str(opt.value);
            select.appendChild(opt);

            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.ModulationType.PRISCILLA_MODULATION_EIGHT_PSK;
            opt.innerHTML = get_modulation_str(opt.value);
            select.appendChild(opt);
            break;
        default:
            select.disabled = true;
            select.options.length = 0;

            opt = document.createElement('option');
            opt.value = proto.priscilla_common_api.ModulationType.PRISCILLA_MODULATION_NOT_USED;
            opt.innerHTML = "N.A.";
            select.appendChild(opt);
    }
    $('select').material_select();
}

function populate_symbol_rate() {
    var prev_val = $('#edit_carrier_symbol_rate').val();
    $('select').material_select('destroy');
    switch (parseInt($('#edit_carrier_network_type').val())) {
        case proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_FL:
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_FL:
            $('#edit_carrier_symbol_rate').replaceWith('<input id="edit_carrier_symbol_rate" type="text" value="N.A." disabled="disabled">');
            break;
        case proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_RL:
            $('#edit_carrier_symbol_rate').replaceWith('<select id="edit_carrier_symbol_rate">' +
                '<option value="156.200">156.2</option>' +
                '<option value="312.500">312.5</option>' +
                '<option value="625.000">625</option>' +
                '<option value="1250.000">1250</option>' +
                '<option value="2500.000">2500</option>' +
                '</select>');
            select_option('edit_carrier_symbol_rate', prev_val);
            break;
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_FL:
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_RL:
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_RL:
            $('#edit_carrier_symbol_rate').replaceWith('<input id="edit_carrier_symbol_rate" type="text" value="' + prev_val + '">');
            break;
        default:
            $('#edit_carrier_symbol_rate').replaceWith('<input id="edit_carrier_symbol_rate" type="text" value="N.A.">');
    }
    $('select').material_select();
}

function populate_code_rate() {
    var prev_val = $('#edit_carrier_code_rate').val();
    $('select').material_select('destroy');
    switch (parseInt($('#edit_carrier_network_type').val())) {
        case proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_FL:
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_FL:
            $('#edit_carrier_code_rate').replaceWith('<input id="edit_carrier_code_rate" type="text" value="N.A." disabled="disabled">');
            break;
        case proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_RL:
            $('#edit_carrier_code_rate').replaceWith('<select id="edit_carrier_code_rate">' +
                '<option>0.667</option>' +
                '<option>0.857</option>' +
                '</select>');
            select_option('edit_carrier_code_rate', prev_val);
            break;
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_FL:
            $('#edit_carrier_code_rate').replaceWith('<select id="edit_carrier_code_rate">' +
                '<option>0.495</option>' +
                '<option>0.660</option>' +
                '<option>0.793</option>' +
                '<option>0.879</option>' +
                '</select>');
            select_option('edit_carrier_code_rate', prev_val);
            break;
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_RL:
            $('#edit_carrier_code_rate').replaceWith('<select id="edit_carrier_code_rate">' +
                '<option>0.660</option>' +
                '<option>0.793</option>' +
                '</select>');
            select_option('edit_carrier_code_rate', prev_val);
            break;
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_RL:
            switch ($('#edit_carrier_frame_format').val()) {
                case "1":
                    switch ($('#edit_carrier_modulation').val()) {
                        case "4":
                            $('#edit_carrier_code_rate').replaceWith('<select id="edit_carrier_code_rate">' +
                                '<option>0.500</option>' +
                                '<option>0.667</option>' +
                                '<option>0.750</option>' +
                                '<option>0.800</option>' +
                                '<option>0.857</option>' +
                                '</select>');
                            select_option('edit_carrier_code_rate', prev_val);
                            break;
                        case "8":
                            $('#edit_carrier_code_rate').replaceWith('<select id="edit_carrier_code_rate">' +
                                '<option>0.667</option>' +
                                '<option>0.800</option>' +
                                '</select>');
                            select_option('edit_carrier_code_rate', prev_val);
                            break;
                    }
                    break;
                case "2":
                    switch ($('#edit_carrier_modulation').val()) {
                        case "4":
                            $('#edit_carrier_code_rate').replaceWith('<select id="edit_carrier_code_rate">' +
                                '<option>0.750</option>' +
                                '</select>');
                            select_option('edit_carrier_code_rate', prev_val);
                            break;
                        case "8":
                            $('#edit_carrier_code_rate').replaceWith('<select id="edit_carrier_code_rate">' +
                                '<option>0.667</option>' +
                                '<option>0.857</option>' +
                                '</select>');
                            select_option('edit_carrier_code_rate', prev_val);
                            break;
                    }
                    break;
            }
            break;
        default:
            $('#edit_carrier_code_rate').replaceWith('<input id="edit_carrier_code_rate" type="text" value="">');
    }
    $('select').material_select();

    $('#edit_carrier_code_rate').on('change', function () {
        populate_block_size();
    });
}

function populate_block_size() {
    var prev_val = $('#edit_carrier_block_size').val();
    $('select').material_select('destroy');
    switch (parseInt($('#edit_carrier_network_type').val())) {
        case proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_FL:
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_FL:
        case proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_RL:
            $('#edit_carrier_block_size').replaceWith('<input id="edit_carrier_block_size" type="text" value="N.A." disabled="disabled">');
            break;
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_FL:
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_RL:
            switch ($('#edit_carrier_code_rate').val()) {
                case "0.495":
                    $('#edit_carrier_block_size').replaceWith('<select id="edit_carrier_block_size">' +
                        '<option value="4096">4096</option>' +
                        '</select>');
                    break;
                case "0.660":
                    $('#edit_carrier_block_size').replaceWith('<select id="edit_carrier_block_size">' +
                        '<option value="1024">1024</option>' +
                        '</select>');
                    break;
                case "0.793":
                    $('#edit_carrier_block_size').replaceWith('<select id="edit_carrier_block_size">' +
                        '<option value="4096">4096</option>' +
                        '</select>');
                    break;
                case "0.879":
                    $('#edit_carrier_block_size').replaceWith('<select id="edit_carrier_block_size">' +
                        '<option value="16384">16384</option>' +
                        '</select>');
                    break;
            }
            break;
        case proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_RL:
            switch ($('#edit_carrier_code_rate').val()) {
                case "0.500":
                    $('#edit_carrier_block_size').replaceWith('<select id="edit_carrier_block_size">' +
                        '<option value="1600">1600</option>' +
                        '<option value="2720">2720</option>' +
                        '</select>');
                    select_option('edit_carrier_block_size', prev_val);
                    break;
                case "0.667":
                    switch ($('#edit_carrier_modulation').val()) {
                        case "4":
                            $('#edit_carrier_block_size').replaceWith('<select id="edit_carrier_block_size">' +
                                '<option value="5256">5256</option>' +
                                '</select>');
                            break;
                        case "8":
                            $('#edit_carrier_block_size').replaceWith('<select id="edit_carrier_block_size">' +
                                '<option value="1700">1700</option>' +
                                '</select>');
                            break;
                    }
                    break;
                case "0.750":
                    $('#edit_carrier_block_size').replaceWith('<select id="edit_carrier_block_size">' +
                        '<option value="1067">1067</option>' +
                        '<option value="1814">1814</option>' +
                        '</select>');
                    select_option('edit_carrier_block_size', prev_val);
                    break;
                case "0.800":
                    $('#edit_carrier_block_size').replaceWith('<select id="edit_carrier_block_size">' +
                        '<option value="4380">4380</option>' +
                        '</select>');
                    break;
                case "0.857":
                    $('#edit_carrier_block_size').replaceWith('<select id="edit_carrier_block_size">' +
                        '<option value="4088">4088</option>' +
                        '</select>');
                    break;
            }
            break;
        default:
            $('#edit_carrier_block_size').replaceWith('<input id="edit_carrier_block_size" type="text" value="">');
    }
    $('select').material_select();
}

function add_new_carrier() {
    rowSelected = -1;

    var device_name_select = document.getElementById('edit_carrier_device_name');
    device_name_select.options.length = 0;
    for (var i = 0; i < devices.length; i++) {
        if (devices[i].is_enabled) {
            var name = devices[i].name;
            var opt = document.createElement('option');
            opt.value = devices[i].type;
            opt.innerHTML = name;
            device_name_select.appendChild(opt);
        }
    }
    $('select').material_select();

    $('#edit_carrier_device_name').change();
    $('#edit_carrier_modal').openModal();
}

function add_carrier(is_enabled, demodulator_type, frequency, system_type, symbol_rate, modulation, code_rate, block_size, frame_format) {
    var row_count = $('#table_carriers tbody tr').length;
    var str = '<tr><td><input type="checkbox" id="rl_carrier_enabled_' + row_count + '" ' + (is_enabled == true || is_enabled == "true" ? 'checked="checked"' : '') + '"/><label for="rl_carrier_enabled_' + row_count +
        '"></label></td>';
    str += '<td>' + get_demodulator_type_str(demodulator_type) + '</td>';
    str += '<td>' + numeral(frequency).divide(1e6).toFixed(3) + '</td>';
    str += '<td>' + get_network_type_str(system_type) + '</td>';
    str += '<td>' + (symbol_rate == 0 ? '-' : numeral(symbol_rate).divide(1e3).toFixed(3)) + '</td>';
    str += '<td>' + (modulation == 0 ? '-' : get_modulation_str(modulation)) + '</td>';
    str += '<td>' + (code_rate == 0 ? '-' : code_rate) + '</td>';
    str += '<td>' + (block_size == 0 ? '-' : block_size) + '</td>';
    str += '<td>' + (frame_format == 0 ? '-' : frame_format) + '</td>';
    str += '<td><img src="icons/ic_clear_black_18px.svg" style="cursor: pointer;" onclick="remove_carrier($(this))"></i></td></tr>';
    $('#table_carriers tbody').append(str);
}

function add_fl_based_rl_carrier(is_enabled, frequency, system_type, symbol_rate, modulation, code_rate) {
    var row_count = $('#table_rl_carriers_from_fl tbody tr').length;
    var str = '<tr><td><input type="checkbox" id="fl_based_rl_carrier_enabled_' + row_count + '" ' + (is_enabled == true || is_enabled == "true" ? 'checked="checked"' : '') + '"/><label for="fl_based_rl_carrier_enabled_' + row_count +
        '"></label></td>';
    str += '<td>' + numeral(frequency).divide(1e6).toFixed(3) + '</td>';
    str += '<td>' + get_network_type_str(system_type) + '</td>';
    str += '<td>' + (symbol_rate == 0 ? '-' : numeral(symbol_rate).divide(1e3).toFixed(3)) + '</td>';
    str += '<td>' + (modulation == 0 ? '-' : get_modulation_str(modulation)) + '</td>';
    str += '<td>' + (code_rate == 0 ? '-' : code_rate) + '</td></tr>';
    $('#table_rl_carriers_from_fl tbody').append(str);
}

function remove_carrier(row) {
    row.closest('tr').remove();
}

function edit_carrier() {
    $('#table_carriers').find('tr').click(function () {
        rows = $('#table_carriers tbody').find('tr');

        rowSelected = $(this).index();

        var $row = $(this);

        device_name_select = document.getElementById('edit_carrier_device_name');
        device_name_select.options.length = 0;

        selected_name = $row.find(':nth-child(2)').text();
        for (var i = 0; i < devices.length; i++) {
            if (devices[i].is_enabled) {
                var name = devices[i].name;
                var opt = document.createElement('option');
                opt.value = name;
                opt.innerHTML = name;

                device_name_select.appendChild(opt);
            }

            if (name == selected_name) opt.selected = true;
        }
        $('select').material_select();

        document.getElementById('edit_carrier_device_type').value = $row.find(':nth-child(3)').text();

        update_carrier_network_types($row.find(':nth-child(4)').text());

        document.getElementById('edit_carrier_frequency').value = $row.find(':nth-child(6)').text();

        select_option('edit_carrier_frame_format', $row.find(':nth-child(7)').text());

        select_option('edit_carrier_modulation', $row.find(':nth-child(8)').text());

        if ($('#edit_carrier_symbol_rate').is('input')) {
            document.getElementById('edit_carrier_symbol_rate').value = $row.find(':nth-child(9)').text();
        } else {
            select_option('edit_carrier_symbol_rate', $row.find(':nth-child(9)').text());
        }

        if ($('#edit_carrier_code_rate').is('input')) {
            document.getElementById('edit_carrier_code_rate').value = $row.find(':nth-child(10)').text();
        } else {
            select_option('edit_carrier_code_rate', $row.find(':nth-child(10)').text());
        }

        if ($('#edit_carrier_block_size').is('input')) {
            document.getElementById('edit_carrier_block_size').value = $row.find(':nth-child(12)').text();
        } else {
            select_option('edit_carrier_block_size', $row.find(':nth-child(12)').text());
        }

    });

    $('#edit_carrier_modal').openModal();
}

function edit_carrier_ok() {
    var is_valid = validate_carrier();
    if (!is_valid) return;

    if (rowSelected == -1) {
        add_carrier(true,
            val_of_enum(proto.priscilla_common_api.DemodulatorType, $('#edit_carrier_device_type').val()),
            document.getElementById('edit_carrier_network_type').value,
            numeral(document.getElementById('edit_carrier_frequency').value).multiply(1e6).value(),
            $("#edit_carrier_frame_format option:selected").html() == "N.A." ? 0 : $("#edit_carrier_frame_format option:selected").html(),
            $("#edit_carrier_modulation option:selected").val() == "N.A." ? 0 : $("#edit_carrier_modulation option:selected").val(),
            $('#edit_carrier_symbol_rate').is('select') ? ($('#edit_carrier_symbol_rate option:selected').val() == "N.A." ? 0 : $('#edit_carrier_symbol_rate option:selected').val()) : ($('#edit_carrier_symbol_rate').val() == "N.A." ? 0 : $('#edit_carrier_symbol_rate').val()),
            $('#edit_carrier_code_rate').is('select') ? ($('#edit_carrier_code_rate option:selected').val() == "N.A." ? 0 : $('#edit_carrier_code_rate option:selected').val()) : ($('#edit_carrier_code_rate').val() == "N.A." ? 0 : $('#edit_carrier_code_rate').val()),
            $('#edit_carrier_block_size').is('select') ? ($('#edit_carrier_block_size option:selected').val() == "N.A." ? 0 : $('#edit_carrier_block_size option:selected').val()) : ($('#edit_carrier_block_size').val() == "N.A." ? 0 : $('#edit_carrier_block_size').val()))

    } else {
        var selectedRow = $('#table_carriers tbody').find('tr')[rowSelected];
        selectedRow.children[2].innerHTML = document.getElementById('edit_carrier_device_type').value;
        selectedRow.children[3].innerHTML = document.getElementById('edit_carrier_network_type').value;
        selectedRow.children[5].innerHTML = numeral(document.getElementById('edit_carrier_frequency').value).multiply(1e6).value();
        selectedRow.children[6].innerHTML = $("#edit_carrier_frame_format option:selected").html();
        selectedRow.children[7].innerHTML = $("#edit_carrier_modulation option:selected").html();
        selectedRow.children[8].innerHTML = $('#edit_carrier_symbol_rate').is('select') ? $('#edit_carrier_symbol_rate option:selected').val() : $('#edit_carrier_symbol_rate').val().trim();
        selectedRow.children[9].innerHTML = $('#edit_carrier_code_rate').is('select') ? $('#edit_carrier_code_rate option:selected').val() : $('#edit_carrier_code_rate').val();
        selectedRow.children[11].innerHTML = $('#edit_carrier_block_size').is('select') ? $('#edit_carrier_block_size option:selected').val() : $('#edit_carrier_block_size').val();
    }

    $('#edit_carrier_modal').closeModal();
}

function validate_carrier() {
    $('#edit_carrier_modal').find('input').removeClass('invalid');

    field = $('#edit_carrier_frequency');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }
    var val = Number(field.val());
    if (isNaN(val) || val < 950 || val > 2150) {
        field.addClass('invalid');
        return false;
    }

    var network_type = parseInt($('#edit_carrier_network_type').val());
    if (network_type == proto.priscilla_common_api.SystemType.PRISCILLA_VIASAT_LINKSTAR_RL ||
        network_type == proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_FL ||
        network_type == proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_INFINITI_RL ||
        network_type == proto.priscilla_common_api.SystemType.PRISCILLA_IDIRECT_EVOLUTION_RL) {
        field = $('#edit_carrier_symbol_rate');
        field.removeClass('invalid');
        if (field.val() == null || field.val().trim() == "") {
            field.addClass('invalid');
            return false;
        }
        val = Number(field.val());
        if (isNaN(val)) {
            field.addClass('invalid');
            return false;
        }
    }

    return true;
}

function update_device_names(old_device_name, new_device_name) {
    for (var i = 0; i < devices.length; i++) {
        if (devices[i].name == old_device_name) {
            devices[i].name = new_device_name;
            break;
        }
    }
}

function update_device_names_in_carriers_table(old_device_name, new_device_name) {
    rows = $('#table_carriers tbody').find('tr');

    for (var i = 0; i < rows.length; ++i) {
        if (rows[i].children[1].innerHTML == old_device_name) {
            rows[i].children[1].innerHTML = new_device_name;
        }
    }
}

function add_new_decoder() {
    rowSelected = -1;

    device_name_select = document.getElementById('edit_decoder_device_name');
    device_name_select.options.length = 0;
    for (var i = 0; i < devices.length; i++) {
        if (devices[i].type == "IDD" && devices[i].is_enabled) {
            name = devices[i].name;
            var opt = document.createElement('option');
            opt.value = name;
            opt.innerHTML = name;
            device_name_select.appendChild(opt);
        }
    }
    $('select').material_select();

    $('#edit_decoder_modal').openModal();
}

function add_decoder(is_enabled, device_name, ip_address, username, password) {
    var row_count = $('#table_decoders tbody tr').length;
    var str = '<tr><td><input type="checkbox" id="decoder_enabled_' + row_count + '" ' + (is_enabled == true || is_enabled == "true" ? 'checked="checked"' : '') + '"/><label for="decoder_enabled_' + row_count + '"></label></td> \
                   <td>' + device_name + '</td> \
                   <td>' + ip_address + '</td> \
                   <td>' + username + '</td> \
                   <td>' + password + '</td> \
                   <td><img src="icons/ic_mode_edit_black_18px.svg" style="cursor: pointer;" onclick="edit_decoder()"></i></td> \
                   <td><img src="icons/ic_clear_black_18px.svg" style="cursor: pointer;" onclick="remove_decoder()"></i></td></tr>';
    $('#table_decoders tbody').append(str);
}

function remove_decoder() {
    $('#table_decoders tbody').find('tr').click(function () {
        $(this).remove();
    });
}

function edit_decoder() {
    $('#table_decoders').find('tr').click(function () {
        rowSelected = $(this).index();

        var $row = $(this);

        device_name_select = document.getElementById('edit_decoder_device_name');
        device_name_select.options.length = 0;

        selected_name = $row.find(':nth-child(2)').text();
        for (var i = 0; i < devices.length; i++) {
            if (devices[i].type == "IDD" && devices[i].is_enabled) {
                name = devices[i].name;
                var opt = document.createElement('option');
                opt.value = name;
                opt.innerHTML = name;
                device_name_select.appendChild(opt);
            }

            if (name == selected_name) opt.selected = true;
        }
        $('select').material_select();

        document.getElementById('edit_decoder_ip_address').value = $row.find(':nth-child(3)').text();
        document.getElementById('edit_decoder_username').value = $row.find(':nth-child(4)').text();
        document.getElementById('edit_decoder_password').value = $row.find(':nth-child(5)').text();
    });

    $('#edit_decoder_modal').openModal();
}

function edit_decoder_ok() {
    var is_valid = validate_decoder();
    if (!is_valid) return;

    if (rowSelected == -1) {
        add_decoder(true,
            document.getElementById('edit_decoder_device_name').value,
            document.getElementById('edit_decoder_ip_address').value.trim(),
            document.getElementById('edit_decoder_username').value.trim(),
            document.getElementById('edit_decoder_password').value.trim())

    } else {
        var selectedRow = $('#table_decoders tbody').find('tr')[rowSelected];
        selectedRow.children[1].innerHTML = document.getElementById('edit_decoder_device_name').value;
        selectedRow.children[2].innerHTML = document.getElementById('edit_decoder_ip_address').value.trim();
        selectedRow.children[3].innerHTML = document.getElementById('edit_decoder_username').value.trim();
        selectedRow.children[4].innerHTML = document.getElementById('edit_decoder_password').value.trim();
    }

    $('#edit_decoder_modal').closeModal();
}

function validate_decoder() {
    $('#edit_decoder_modal').find('input').removeClass('invalid');

    var field = $('#edit_decoder_ip_address');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }
    if (!check_ip_address(field.val())) {
        field.addClass('invalid');
        return;
    }

    field = $('#edit_decoder_username');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }

    field = $('#edit_decoder_password');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }

    return true;
}

function update_device_names_in_decoders_table(old_device_name, new_device_name) {
    rows = $('#table_decoders tbody').find('tr');

    for (var i = 0; i < rows.length; ++i) {
        if (rows[i].children[1].innerHTML == old_device_name) {
            rows[i].children[1].innerHTML = new_device_name;
        }
    }
}

function add_new_network_id() {
    rowSelected = -1;

    $('#edit_network_id_modal').openModal();
}

function add_network_id(network_id, src_mac_address, dst_mac_address) {
    var row_count = $('#table_network_id_to_mac tbody tr').length;
    var str = '<tr><td>' + network_id + '</td> \
                   <td>' + src_mac_address + '</td> \
                   <td>' + dst_mac_address + '</td> \
                   <td><img src="icons/ic_mode_edit_black_18px.svg" style="cursor: pointer;" onclick="edit_network_id()"></i></td> \
                   <td><img src="icons/ic_clear_black_18px.svg" style="cursor: pointer;" onclick="remove_network_id()"></i></td></tr>';
    $('#table_network_id_to_mac tbody').append(str);
}

function remove_network_id() {
    $('#table_network_id_to_mac tbody').find('tr').click(function () {
        $(this).remove();
    });
}

function edit_network_id() {
    $('#table_network_id_to_mac').find('tr').click(function () {
        rowSelected = $(this).index();

        var $row = $(this);

        document.getElementById('edit_network_id_network_id').value = $row.find(':nth-child(1)').text();
        document.getElementById('edit_network_id_src_mac_address').value = $row.find(':nth-child(2)').text();
        document.getElementById('edit_network_id_dst_mac_address').value = $row.find(':nth-child(3)').text();
    });

    $('#edit_network_id_modal').openModal();
}

function edit_network_id_ok() {
    var is_valid = validate_network_id();
    if (!is_valid) return;

    if (rowSelected == -1) {
        add_network_id(document.getElementById('edit_network_id_network_id').value.trim(),
            document.getElementById('edit_network_id_src_mac_address').value.trim(),
            document.getElementById('edit_network_id_dst_mac_address').value.trim())

    } else {
        var selectedRow = $('#table_network_id_to_mac tbody').find('tr')[rowSelected];
        selectedRow.children[0].innerHTML = document.getElementById('edit_network_id_network_id').value.trim();
        selectedRow.children[1].innerHTML = document.getElementById('edit_network_id_src_mac_address').value.toUpperCase().trim();
        selectedRow.children[2].innerHTML = document.getElementById('edit_network_id_dst_mac_address').value.toUpperCase().trim();
    }

    $('#edit_network_id_modal').closeModal();
}

function validate_network_id() {
    var field = $('#edit_network_id_network_id');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }

    field = $('#edit_network_id_src_mac_address');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }
    if (!check_mac_address(field.val())) {
        field.addClass('invalid');
        return;
    }

    field = $('#edit_network_id_dst_mac_address');
    field.removeClass('invalid');
    if (field.val() == null || field.val().trim() == "") {
        field.addClass('invalid');
        return false;
    }
    if (!check_mac_address(field.val())) {
        field.addClass('invalid');
        return;
    }

    return true;
}

function get_FEC_value_from_string(str) {
    var fec = FECStringToValueMap[str];
    return (fec != undefined) ? fec : 0;
}

function get_FEC_string_from_value(val) {
    /*Set set = FECStringToValueMap.entrySet();
    Iterator it = set.iterator();
    Map.Entry entry;
    double entryVal;
    while(it.hasNext()) {
        entry = (Map.Entry) it.next();
        entryVal = (double) entry.getValue();
        if(Math.abs(entryVal - val) < 0.002) {
            return (String) entry.getKey();
        }
    }*/
    return "-";
}

function update_capture_mode(mode) {
    if (mode != undefined) g_capture_mode = mode;

    if (g_capture_mode == proto.priscilla_satprobe_api.CaptureMode.PRISCILLA_SATPROBE_CAPTURE_MODE_NORMAL) {
        $("#rdo_capture_mode_normal").attr("checked", true);
        $("#rdo_capture_mode_fl_based").attr("checked", false);

        $('#div_fl_based_carrier_config').addClass('hiddendiv');
        $('#div_carrier_config').removeClass('hiddendiv');
        $('#div_carrier_config').animateCss('fadeIn');
    } else if (g_capture_mode == proto.priscilla_satprobe_api.CaptureMode.PRISCILLA_SATPROBE_CAPTURE_MODE_FL_BASED) {
        $("#rdo_capture_mode_normal").attr("checked", false);
        $("#rdo_capture_mode_fl_based").attr("checked", true);

        $('#div_carrier_config').addClass('hiddendiv');
        $('#div_fl_based_carrier_config').removeClass('hiddendiv');
        $('#div_fl_based_carrier_config').animateCss('fadeIn');
    }
}

function get_rl_carriers_from_fl() {
    if ($('#btn_get_rl_carriers_from_fl').html() == 'Get RL Carriers') {
        var msg = new proto.priscilla_satprobe_api.get_rl_carriers_from_fl_message();
        msg.setHeader(create_header(proto.priscilla_common_api.MessageType.PRISCILLA_GET_FL_BASED_RL_CARRIERS, $('#header_request_id').val(), $('#header_body_length').val()));

        msg.setSystemType($('#carrier_config_fl_based_system_type option:selected').val());
        msg.setFlFrequency(numeral($('#carrier_config_fl_based_frequency').val()).multiply(1e6));

        var bin = msg.serializeBinary();
        ws_command.send(bin);

        $('#btn_get_rl_carriers_from_fl').addClass('disabled');
    } else {
        var msg = new proto.priscilla_satprobe_api.cancel_get_rl_carriers_from_fl_message();
        msg.setHeader(create_header(proto.priscilla_common_api.MessageType.PRISCILLA_CANCEL_GET_FL_BASED_RL_CARRIERS, $('#header_request_id').val(), $('#header_body_length').val()));

        msg.setSystemType($('#carrier_config_fl_based_system_type option:selected').val());
        
        var bin = msg.serializeBinary();
        ws_command.send(bin);

        $('#btn_get_rl_carriers_from_fl').addClass('disabled');
    }
}
