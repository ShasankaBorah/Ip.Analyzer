
var ws_command;
var ws_messages;
var g_data;
var g_data_pair_only = []; //array to filled with pairs data only
var g_database_obj;
var two_way_only = false;
var two_way_table_data; // =fill the variable with the data

let next; //used to scroll to next page
var max_size;
let next_pairs;
var start;
let prev;
var rows_per_page = 100;
var limit = rows_per_page;
var table_data;
var from_database = false;
var table_result;

$(document).ready(function () {
    initialise();
});

function initialise() {
    var host = window.location.host;
    ws_command = new WebSocket("ws://" + host + "/ws/command");

    onLoad_data_refresh();


    ws_command.onmessage = function (evt) {
        parse_command_reply(evt.data);
    }

    ws_message = new WebSocket("ws://" + host + "/ws/progress_message");
    ws_message.onmessage = function (evt) {
        parse_message(evt.data);
    }

    ws_message = new WebSocket("ws://" + host + "/ws/message");
    ws_message.onmessage = function (evt) {
        Materialize.toast(evt.data, 1000);
    }

    table_result = $('#table_result_dns tbody');
    $(table_result).on("click", "tr", function (e) {

        let str1 = $(this).find("td:eq(1)").text();
        srcIPDns = str1; /*to display the ip in the table after the row is cicked */
        dstIPDns = $(this).find("td:eq(2)").text(); /*to display the ip in the table after the row is cicked */
        str1 += "_" + $(this).find("td:eq(2)").text();

        //display_seq_data($(e.currentTarget).children(":nth-child(1)").html());
        $('#table_result_dns tr').removeClass('green lighten-2');
        $(this).addClass('green lighten-2');
        ws_command.send("getDnsJson&" + str1);
    });

    $('#top_nav').load("top_nav.html", function () {
        $('#nav_dns').addClass('red lighten-2');
    });

    var pagerOptions = {
        container: $("#pager"),
        page: 0,
        size: 50,
        savePages: false,
    };
    /*******************************************************************************************/

    /**********************************this is the table sorter and pager code******************************************/
    $("#table_result_dns").tablesorter({
        initWidgets: true,
        widgets: ['zebra', 'columns', 'filter']
    }).tablesorterPager(pagerOptions);

} //initialise ends here

function start_dns_analysis() { //fucntion to start dns analysis
    $('#btn_start_dns_analysis').addClass('disabled');
    $('#table_result_dns tbody').empty();
    ws_command.send("start_dns_analysis");
}

function parse_message(data) {
    var obj = JSON.parse(data);
    if (obj.type == "progress") {
        $('#p_current_file').html(obj.filename);
        $('#p_progress').html(numeral(obj.bytesRead).formatNumber() + '\\' + numeral(obj.fileSize).formatNumber() + ' (' + numeral(obj.bytesRead / obj.fileSize * 100).formatNumber(2) + '%)' + '(' + numeral(obj.seconds).formatNumber() + 'sec)');
        if (obj.total_time != undefined) {
            $("#total_time_elapsed").html('Total Time Elapsed: ' + numeral(obj.total_time).formatNumber() + 'sec');
        }
    }
}

function parse_command_reply(data) {
    var obj = JSON.parse(data);
    if (obj.type == "dns_result") {
        console.log("Analysis data received.");
        display_analysis_data(obj);
        $('#btn_start_dns_analysis').removeClass('disabled');
    } else if (obj.type == "load_from_db") {
        console.log("dns data from database received.");
        from_database = true;
        two_way_only = false;
        display_analysis_data(JSON.parse(obj.data));
        $('#btn_load_selected_dbs').removeClass('disabled');
    } else if (obj.type == "dns_database") {
        console.log("Full dns database files received.");
        display_dns_database(obj);
        $('#btn_get_dns_database_all').removeClass('disabled');
    }
    else if (obj.type == "ipJsonResult") {
        var parsedJsonData = JSON.parse(obj.dns_packet_info);
        console.log("ip json received");
        display_json_data_after_click_row(parsedJsonData);
    }
}

function onLoad_data_refresh() {
    ws_command.onopen = function (evt) {
        ws_command.send("get_dns_database_all");
    }
}

function load_from_dns_db() {
    $('#btn_load_from_dns_db').addClass('disabled');
    ws_command.send("load_from_dns_db");
}


function display_dns_database(obj) //for displaying data after loading the json from database		
{
    if (obj.data == undefined) return;

    $.each(obj.data, function (i, item) {
        $('#select_db_list').append($('<option>', {
            value: item,
            text: item
        }));
    });

    $('#select_db_list').material_select();
}

function load_selected_db() {
    $('#btn_load_selected_dbs').addClass('disabled');
    let selected_db = $('#select_db_list :selected').val();
    ws_command.send("load_selected_dns_db&" + selected_db.toString());
}


function display_analysis_data(obj) { //for icmp analysis
    g_data = obj;

    if(obj.streams == undefined)
    {
        stream_data_file_result_body(obj);
        Materialize.toast("No DNS Data");
        return;
    }
    two_way_table_data = obj.streams;

    var j = 0;
    for (i = 0; i < two_way_table_data.length; i++) {
        if ((two_way_table_data[i].folders_FL instanceof Array) && (two_way_table_data[i].folders_RL instanceof Array)) {
            g_data_pair_only[j] = two_way_table_data[i];
            j++;
        }
    }

    stream_data_file_result_body(obj);
    stream_data_pair_result_body(obj);
    initialise_stream_display();
}

function stream_data_file_result_body(obj) { //function to show number of files read , fl files , rl files, fl file path , rl file path
    // set d_num_files here from json
    $('#file_result tbody').empty();

    if (obj.analysis_info[0]) {
        var d_num = obj.analysis_info[0].number_of_files_read;
        document.getElementById("d_num_files").innerHTML = d_num;

        var dtr = '<tr>';
        dtr += '<td>'
        dtr += obj.analysis_info[0].filePathFL;
        dtr += '</td>'

        dtr += '<td>'
        dtr += obj.analysis_info[0].filePathRL;
        dtr += '</td>'

        dtr += '<td>'
        dtr += obj.analysis_info[0].CreatedAt;
        dtr += '</td>'

        if (obj.analysis_info[0].FL_Files != undefined) {
            dtr += '<td>'
            for (j = 0; j < obj.analysis_info[0].FL_Files.length; j++) {
                dtr += obj.analysis_info[0].FL_Files[j].pcapFileFl + ' (' + obj.analysis_info[0].FL_Files[j].size + ' ) ' + '<br>';
            }
            dtr += '</td>'
        } else {
            dtr += '<td>'
            dtr += 'No_Files'
            dtr += '</td>'
        }

        if (obj.analysis_info[0].RL_Files != undefined) {
            dtr += '<td>'
            for (j = 0; j < obj.analysis_info[0].RL_Files.length; j++) {
                dtr += obj.analysis_info[0].RL_Files[j].pcapFileRl + ' (' + obj.analysis_info[0].RL_Files[j].size + ' ) ' + '<br>';
            }
            dtr += '</td>'
        } else {
            dtr += '<td>'
            dtr += 'No_Files'
            dtr += '</td>'
        }


        dtr += '</tr>';
        $('#file_result tbody').append(dtr);
    }
}

function stream_data_pair_result_body(obj) {
    var myMap = new Map();
    for (i = 0; i < obj.streams.length; i++) {
        var stream = obj.streams[i];

        if (stream.folders_FL instanceof Array) {
            for (j = 0; j < stream.folders_FL.length; j++) { //
                if (myMap.get(stream.folders_FL[j]) == undefined) {
                    var mySet = new Set();
                    if (stream.folders_RL instanceof Array) {
                        for (k = 0; k < stream.folders_RL.length; k++) {
                            mySet.add(stream.folders_RL[k]);
                        }
                    }
                    myMap.set(stream.folders_FL[j], mySet);

                } else {
                    var MySet = myMap[stream.folders_FL[j]];
                    if (stream.folders_RL instanceof Array) {
                        for (k = 0; k < stream.folders_RL.length; k++) {
                            mySet.add(stream.folders_RL[k]);
                        }
                    }
                }
            } //

        } //if loop ends folders_AB instanceof Array
        else {
            continue;
        }

    }

    $('#pairs_result tbody').empty();
    var ptr = "";
    for (let [key, value] of myMap) {
        ptr += '<tr>';
        ptr += '<td>' + key + '</td>';
        ptr += '<td>';
        for (val of value) {
            ptr += val + '<br>';
        }
        ptr += '<td>';
        ptr += '</tr>';
    }
    $('#pairs_result tbody').append(ptr);
}

function initialise_stream_display() {
    if (g_data == undefined) return;

    if (from_database == true) {
        limit = rows_per_page;
    }

    table_data = g_data.streams;
    max_size = table_data.length;
    start = 0;

    limit = Math.min(table_data.length, limit);

    // display_req_rep_pairs_only();


    display_stream_data(start, limit);
    //$('#p_table_result_info').html(1 + '-' + limit + '(' + max_size + ')');
}

function display_stream_data(start, limit) { //to display the data in the main table
    table_result.empty();

    if (table_data == undefined || !(table_data instanceof Array)) return;

    for (i = start; i < limit; ++i) {
        var stream = table_data[i];

        var str = '<tr>';
        str += '<td>' + (i + 1) + '</td>';
        str += '<td>' + stream.SrcIp + '</td>';
        str += '<td>' + stream.DstIp + '</td>';
        str += '<td>' + stream.src_dst + '</td>';
        str += '<td>' + stream.dst_src + '</td>';
        str += '<td>';
        if (stream.folders_FL instanceof Array) {
            for (j = 0; j < stream.folders_FL.length; ++j) {
                str += stream.folders_FL[j] + "<br>";
            }
        }
        str += '</td>';
        str += '<td>';
        if (stream.folders_RL instanceof Array) {
            for (j = 0; j < stream.folders_RL.length; ++j) {
                str += stream.folders_RL[j] + "<br>";
            }
        }
        str += '</td>';
        str += '</tr>';
        table_result.append(str);
    }
}

function load_two_way_dns() {
    max_size = g_data_pair_only.length;
    start = 0;
    limit = Math.min(g_data_pair_only.length, limit);
    two_way_only = true;
    funct_to_load_two_way_pairs(start, limit);
    //$('#p_table_result_info').html(1 + '-' + limit + '(' + max_size + ')');

}

function funct_to_load_two_way_pairs(start, limit) // function to display pairs only after #function called by load_two_way_icmp function
{
    table_result.empty();

    if (g_data_pair_only == undefined || !(g_data_pair_only instanceof Array)) return;

    for (i = start; i < limit; i++) {
        var stream = g_data_pair_only[i];
        var pair_str = '<tr>';
        pair_str += '<td>' + (i + 1) + '</td>';
        pair_str += '<td>' + stream.SrcIp + '</td>';
        pair_str += '<td>' + stream.DstIp + '</td>';
        pair_str += '<td>' + stream.src_dst + '</td>';
        pair_str += '<td>' + stream.dst_src + '</td>';
        pair_str += '<td>';
        if (stream.folders_FL instanceof Array) {
            for (j = 0; j < stream.folders_FL.length; j++) {
                pair_str += stream.folders_FL[j] + "<br>";
            }
        }
        pair_str += '</td>';
        pair_str += '<td>';
        if (stream.folders_RL instanceof Array) {
            for (j = 0; j < stream.folders_RL.length; ++j) {
                pair_str += stream.folders_RL[j] + "<br>";
            }
        }
        pair_str += '</td>';
        pair_str += '</tr>';
        table_result.append(pair_str);
    }
}

function load_table_result_next() {
    if (two_way_only == true) {
        if (limit != max_size) {
            next_pairs = limit;
        }

    } else {
        if (limit != max_size) {
            next = limit;
        }
    }

    if (two_way_only == true) {
        if (max_size > next_pairs) {
            limit = limit + rows_per_page;
            limit = Math.min(g_data_pair_only.length, limit);
            table_result.empty();
            funct_to_load_two_way_pairs(next_pairs, limit);
            //$('#p_table_result_info').html((next_pairs + 1) + '-' + limit + '(' + max_size + ')');
        }
    } else if (max_size > next) {
        limit = limit + rows_per_page;
        limit = Math.min(table_data.length, limit);
        table_result.empty();
        display_stream_data(next, limit);
        //$('#p_table_result_info').html((next + 1) + '-' + limit + '(' + max_size + ')');
    }
}

function load_table_result_prev() {
    if (two_way_only == true) {
        if ((limit % 100) == 0) {
            var prev_two_way = limit - (2 * rows_per_page);
            if (prev_two_way >= 0) {
                limit = limit - rows_per_page;
            } else {
                prev_two_way = 0;
                limit = Math.min(rows_per_page, limit);
            }
            table_result.empty();
            funct_to_load_two_way_pairs(prev_two_way, limit);
            //$('#p_table_result_info').html((prev_two_way + 1) + '-' + limit + '(' + max_size + ')');
        } else {
            var k = limit - rows_per_page;
            if (k > 0) {
                var prev_two_way = limit - k;
                if (prev_two_way >= 0) {
                    var v = limit - (2 * rows_per_page);
                    limit = limit - v;
                } else {
                    prev_two_way = 0;
                    limit = Math.min(rows_per_page, limit);
                }
                table_result.empty();
                funct_to_load_two_way_pairs(prev_two_way, limit);
                //$('#p_table_result_info').html((prev_two_way + 1) + '-' + limit + '(' + max_size + ')');
            }

        }
    } else {
        if (limit % 100 == 0) {
            prev = limit - 2 * rows_per_page;
            if (prev >= 0) {
                limit = limit - rows_per_page;
            }
            else {
                prev = 0;
                limit = rows_per_page;
            }
        }
        else {
            let diff = limit - next;
            limit = limit - diff;
            prev = limit - rows_per_page;
        }
        table_result.empty();
        display_stream_data(prev, limit);
        //$('#p_table_result_info').html((prev + 1) + '-' + limit + '(' + max_size + ')');
    }
}


function display_seq_data(idx) {
    if (two_way_only == true) {
        if (idx > 0 && idx <= g_data_pair_only.length) {
            var stream = g_data_pair_only[idx - 1];
        }
    } else {
        if (idx > 0 && idx <= table_data.length) {
            var stream = table_data[idx - 1];
        }
    }

    $('#table_sequence tbody').empty();

    $('#p_seq_src').html(stream.SrcIp);
    $('#p_seq_dst').html(stream.DstIp);

    var str = "";
    for (k = 0; k < stream.sequence_array.length; k++) {
        var req = stream.sequence_array[k].request;
        var rep = stream.sequence_array[k].reply;
        if (req == true && rep == true) {
            str += '<tr class="green">';
        } else {
            str += '<tr>';
        }
        str += '<td>' + (k + 1) + '</td>';
        str += '<td>' + stream.sequence_array[k].id + '</td>';
        str += '<td>' + req + '</td>';
        str += '<td>' + rep + '</td>';
        str += '</tr>';

        /*if (!(k == stream.sequence_array.length - 1)) {
            if (!(1 == (stream.sequence_array[k + 1].sequence_no - stream.sequence_array[k].sequence_no))) {
                var length_gap = stream.sequence_array[k + 1].sequence_no - stream.sequence_array[k].sequence_no;
                for (m = 1; m < length_gap; m++) {
                    var newvar = parseInt(stream.sequence_array[k].sequence_no, 10);
                    var incrementedValue = newvar + m;
                    icr += '<tr style="color:red;">';
                    icr += '<td>' + incrementedValue + '</td>';
                    icr += '<td>' + false + '</td>';
                    icr += '<td>' + false + '</td>';
                    icr += '<td>' + false + '</td>';
                    icr += '</tr>';
                }
            }
        }*/
    }
    $('#table_sequence tbody').append(str);
    // }
}

function get_dns_database_all() {
    $('#btn_get_dns_database_all').addClass('disabled');
    ws_command.send("get_dns_database_all");
}

function load_all_dns_streams() {
    start = 0;
    limit = rows_per_page;
    two_way_only = false;
    max_size = table_data.length;
    display_stream_data(start, limit);
    // $('#p_table_result_info').html(1 + '-' + limit + '(' + max_size + ')');
}


function display_json_data_after_click_row(parsedJsonData) {
    $('#table_sequence tbody').empty();

    for (let i = 0; i < parsedJsonData.length; i++) {
        var json_ = parsedJsonData[i]._source;

        var str = '<tr>';
        str += '<td>' + (i + 1) + '</td>';
        str += '<td>' + json_.layers["dns.id"] + '</td>';
        if(json_.layers["dns.qry.name"] instanceof Array)
        {
            str += '<td>'
            for(let i = 0 ; i < json_.layers["dns.qry.name"].length ; ++i )
            {
                str += json_.layers["dns.qry.name"][i] + '<br>';
            }
            str += '</td>'
        }


        if(json_.layers["dns.resp.name"] instanceof Array)
        {
            str += '<td>'
            for(let i = 0 ; i < json_.layers["dns.resp.name"].length ; ++i )
            {
                str += json_.layers["dns.resp.name"][i] + '<br>';
            }
            str += '</td>'
        }
        //str += '<td>' + json_.layers["dns.qry.name"] + '</td>';
        //str += '<td>' + json_.layers["dns.resp.name"] + '</td>';
        str += '</tr>';
        $('#table_sequence').append(str);

    }

}