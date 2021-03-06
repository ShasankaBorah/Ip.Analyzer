// Declare global variables here
        var ws_command;
        var ws_messages;
        var g_data;
        var g_data_pair_only = []; //array to filled with pairs data only
        var g_database_obj;
        var two_way_only = false;
        var rr_pairs_flag = false;
        var two_way_table_data; // =fill the variable with the data
        var max_size;
        var start;
        let next;
        let prev;
        var rows_per_page = 100;
        var limit = rows_per_page;
        var table_data;
        var from_database = false;
        var ten_subnet = /^10\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$/;
        var one_nine_teo_subnet = /^192\.168\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$/;
        var one_seven_2_subnet = /^172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$/;
        var reserved_ip = /^100\.(6[4-9]|[7-9][0-9]|1([0-1][0-9]|2[0-7]))\.(0\.(0[ -9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))|([1-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))$/;
        var excludePrivateIp;
        var table_result;
        var rr_pairs_data = [];

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

            table_result = $('#table_result_icmp tbody');

            $(table_result).delegate("tr", "click", function (e) {
                   
                display_seq_data($(e.currentTarget).children(":nth-child(1)").html());    
                $('#table_result_icmp tr').removeClass('green lighten-2');
                $(e.currentTarget).addClass('green lighten-2');
            });

            $('#top_nav').load("top_nav.html", function () {
                $('#nav_icmp').addClass('red lighten-2');
            });

            /******************************************pager options*********************************/
            var pagerOptions = {
                container: $("#pager"),
                page: 0,
                size: 50,
                savePages: false,
            };
            /*******************************************************************************************/

            /**********************************this is the table sorter and pager code******************************************/
            $("#table_result_icmp").tablesorter({
                initWidgets: true,
                widgets: ['zebra', 'columns', 'filter']
            }).tablesorterPager(pagerOptions);
            /*******************************************************************************************************************/
        }


        function parse_command_reply(data) {
            var obj = JSON.parse(data);
            if (obj.type == "icmp_result") {
                console.log("Analysis data received.");
                display_analysis_data(obj);
                $('#btn_start_icmp_analysis').removeClass('disabled');
            } else if (obj.type == "load_from_db") {
                console.log("icmp data from database received.");
                from_database = true;
                two_way_only = false;
                display_analysis_data(JSON.parse(obj.data));
                $('#btn_load_selected_dbs').removeClass('disabled');
            } else if (obj.type == "icmp_database") {
                console.log("Full icmp database files received.");
                display_icmp_database(obj);
                //$('#btn_get_icmp_database_all').removeClass('disabled');
            }
        }

        function onLoad_data_refresh() {
            ws_command.onopen = function (evt) {
                ws_command.send("get_icmp_database_all");
            }
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

            if (obj.type == "api_progress") {
                $('#api_p_progress').html(numeral(obj.totalSetRead).formatNumber() + '\\' + numeral(obj.fileSize).formatNumber());
            }
        }

        function start_icmp_analysis() {

            excludePrivateIp = false;
            if ($('#exclude_private_ip').get(0).checked) {
                excludePrivateIp = true;
            }
            $('#btn_start_icmp_analysis').addClass('disabled');
            $('#table_result_icmp tbody').empty();
            $('#table_sequence_2 tbody').empty();
            $('#table_sequence tbody').empty();
            ws_command.send("start_icmp_analysis&" + excludePrivateIp);
        }

        /**************************TO DISPLAY DATA AFTER ANALYSIS IS DONE OR DATABASE FILE IS LOADED**************************************************/
        function display_analysis_data(obj) {

            if (obj.streams == undefined) {
                Materialize.toast('No public IP data available !!', 4000);
                return;
            }

            g_data = obj;
            two_way_table_data = obj.streams;

            var j = 0;
            var c = 0;
            if (obj.streams != undefined) {
                for (i = 0; i < two_way_table_data.length; i++) {
                    if ((two_way_table_data[i].folders_FL instanceof Array) && (two_way_table_data[i].folders_RL instanceof Array)) {
                        g_data_pair_only[j] = two_way_table_data[i];
                        j++;
                    }

                    if (two_way_table_data[i].sequence_array != undefined) {
                        let rr_count = 0;
                        for (let k = 0; k < two_way_table_data[i].sequence_array.length; k++) {
                            if ((two_way_table_data[i].sequence_array[k].request == true) && (two_way_table_data[i].sequence_array[k].reply == true)) {
                                rr_count++;
                                if (rr_count > 0) {
                                    rr_pairs_data[c] = two_way_table_data[i];
                                    c++;
                                    break;
                                }
                            }

                        }

                    }
                }
            }

            stream_data_file_result_body(obj);
            initialise_stream_display();


        }

        /**************************************************************************************************************************************************/

        /******************************** DISPLAYS INFO ABOUT THE FL RL FOLDER PATH , TIME OF ANALYSIS AND FILES READ**************************************/
        function stream_data_file_result_body(obj) {
            $('#file_result tbody').empty();

            if (obj.analysis_info) {
                var d_num = obj.analysis_info[0].Total_files_read;
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
                        dtr += obj.analysis_info[0].FL_Files[j].pcapFileFl + ' (' + obj.analysis_info[0].FL_Files[j].size + ')' + '<br>';
                    }
                    dtr += '</td>'
                } else {
                    dtr += '<td>'
                    dtr += "No_files";
                    dtr += '</td>'
                }

                if (obj.analysis_info[0].RL_Files != undefined) {
                    dtr += '<td>'
                    for (j = 0; j < obj.analysis_info[0].RL_Files.length; j++) {
                        dtr += obj.analysis_info[0].RL_Files[j].pcapFileRl + ' (' + obj.analysis_info[0].RL_Files[j].size + ')' + '<br>';
                    }
                    dtr += '</td>'
                } else {
                    dtr += '<td>'
                    dtr += "No_files";
                    dtr += '</td>'
                }

                dtr += '</tr>';
                $('#file_result tbody').append(dtr);
            }
        }
        /************************************************************************************************************************************************/

        /********************************IT CALLS DISPLAY STREAM DATA TO SHOW THE DATA IN THE TABLE, AND SETS START AND LIMIT VALUE****************************************************/
        function initialise_stream_display() {
            if (g_data == undefined) return;

            if (from_database == true) {
                limit = rows_per_page;
            }

            table_data = g_data.streams;
            // max_size = table_data.length;
            // start = 0;

            // limit = Math.min(table_data.length, limit);

            display_stream_data(/*start, limit*/);
            //$('#p_table_result_info').html(1 + '-' + limit + '(' + max_size + ')');
        }
        /*****************************************************************************************************************************************************************************/


        /*********************************FUCNTION TO DISPLAY THE DATA IN THE TABLE***************************************************************************************************/
        function display_stream_data(start, limit) {
            table_result.empty();

            if (table_data == undefined || !(table_data instanceof Array)) return;

            for (i = 0; i < /*limit*/table_data.length; ++i) {
                var stream = table_data[i];
                var str = '<tr>';
                str += '<td>' + (i + 1) + '</td>';
                str += '<td>' + stream.SrcIp + '</td>';

                if (ipCompare_to_private(stream.SrcIp)) {
                    str += '<td>' + "privateIP" + '</td>';
                }
                else if (stream.src_info == "NA") {
                    str += '<td>' + "NA" + '</td>';
                }
                else {
                    str += '<td>' + stream.src_info.countryName + '</td>';
                }

                str += '<td>' + stream.DstIp + '</td>';

                if (ipCompare_to_private(stream.DstIp)) {
                    str += '<td>' + "privateIP" + '</td>';
                }
                else if (stream.dst_info == "NA") {
                    str += '<td>' + "NA" + '</td>';
                }
                else {
                    str += '<td>' + stream.dst_info.countryName + '</td>';
                }

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

                if (stream.sequence_array != undefined) {
                    str += '<td>';
                    let count = 0;
                    for (let k = 0; k < stream.sequence_array.length; ++k) {
                        totalCount = stream.sequence_array.length;
                        if (stream.sequence_array[k].request == true && stream.sequence_array[k].reply == true) {
                            count += 1;
                        }

                    }
                    str += count + '</td>';

                    let roundTimeArray = [];

                    let minMax = calculateMinMaxTime(stream.sequence_array);

                    str += '<td>';
                    str += minMax[0];
                    str += '</td>';

                    str += '<td>';
                    str += minMax[1];
                    str += '</td>';

                    str += '<td>';
                    str += minMax[2]
                    str += '</td>';

                    str += '</tr>';
                    table_result.append(str);
                }
                else {
                    str += '<td>' + 'NA' + '</td>';
                    str += '<td>' + 'NA' + '</td>';
                    str += '<td>' + 'NA' + '</td>';
                    str += '<td>' + 'NA' + '</td>';
                    str += '</tr>';
                    table_result.append(str);
                }

            }

            $('#table_result_icmp').tablesorter().trigger('update');

        }


        /*****************************************COMPARES THE SRC AND DST STRING TO CHECK IF ITS PRIVATE OR PUBLIC*****************************************************************
        ******************************************************* TRUE == PRIVATE : FALSE == PUBLIC***********************************************************************************
        ****************************************************************************************************************************************************************************/
        function ipCompare_to_private(ip) {

            if (ten_subnet.test(ip)) {
                return true;
            }
            else if (one_nine_teo_subnet.test(ip)) {
                return true;
            }
            else if (one_seven_2_subnet.test(ip)) {
                return true;
            }
            else if (reserved_ip.test(ip)) {
                return true;
            }
            else
                return false;
        }
        /********************************************************************************************************************************************************************************/


        // /*****************************************DISPLAYS PAIR ONLY AFTER THIS FUNCTION IS CALLED BY THE LOAD_TWO_WAY_ICMP_PAIRS*****************************************************/
        // function funct_to_load_two_way_pairs(start, limit) {
        //     table_result.empty();


        //     if (g_data_pair_only == undefined || !(g_data_pair_only instanceof Array)) return;

        //     for (i = start; i < limit; i++) {
        //         var stream = g_data_pair_only[i];
        //         var pair_str = '<tr>';
        //         pair_str += '<td>' + (i + 1) + '</td>';
        //         pair_str += '<td>' + stream.SrcIp + '</td>';
        //         //for src ip 
        //         if (ipCompare_to_private(stream.SrcIp)) {
        //             pair_str += '<td>' + "privateIP" + '</td>';
        //         }
        //         else if (stream.src_info == "NA") {
        //             pair_str += '<td>' + "NA" + '</td>';
        //         }
        //         else {
        //             pair_str += '<td>' + stream.src_info.countryName + '</td>';
        //         }

        //         pair_str += '<td>' + stream.DstIp + '</td>';

        //         if (ipCompare_to_private(stream.DstIp)) {
        //             pair_str += '<td>' + "privateIP" + '</td>';
        //         }
        //         else if (stream.dst_info == "NA") {
        //             pair_str += '<td>' + "NA" + '</td>';
        //         }
        //         else {
        //             pair_str += '<td>' + stream.dst_info.countryName + '</td>';
        //         }
        //         pair_str += '<td>' + stream.src_dst + '</td>';
        //         pair_str += '<td>' + stream.dst_src + '</td>';
        //         pair_str += '<td>';
        //         if (stream.folders_FL instanceof Array) {
        //             for (j = 0; j < stream.folders_FL.length; j++) {
        //                 pair_str += stream.folders_FL[j] + "<br>";
        //             }
        //         }
        //         pair_str += '</td>';
        //         pair_str += '<td>';
        //         if (stream.folders_RL instanceof Array) {
        //             for (j = 0; j < stream.folders_RL.length; ++j) {
        //                 pair_str += stream.folders_RL[j] + "<br>";
        //             }
        //         }
        //         pair_str += '</td>';


        //         pair_str += '<td>';
        //         let count = 0;
        //         for (let k = 0; k < stream.sequence_array.length; ++k) {
        //             totalCount = stream.sequence_array.length;
        //             if (stream.sequence_array[k].request == true && stream.sequence_array[k].reply == true) {
        //                 count += 1;
        //             }

        //         }
        //         pair_str += count + '</td>';


        //         let pairMinMax = calculateMinMaxTime(stream.sequence_array);

        //         pair_str += '<td>';
        //         pair_str += pairMinMax[0]
        //         pair_str += '</td>';

        //         pair_str += '<td>';
        //         pair_str += pairMinMax[1]
        //         pair_str += '</td>';

        //         pair_str += '<td>';
        //         pair_str += pairMinMax[2]
        //         pair_str += '</td>';

        //         pair_str += '</tr>';
        //         table_result.append(pair_str);
        //     }
        // }
        // /***********************************************************************************************************************************************************************************/


        // /*******************************************CALLED WHEN THE BUTTON -> LOAD TWO WAY IS BEING CLICKED TO SHOW THE DATA WITH BOTH FL AND RL FILES PRESENT****************************/
        // function load_two_way_icmp() { //to load two way data
        //     $('#btn_load_two_way_icmp').addClass('disabled');
        //     $('#btn_rr_pairs').removeClass('disabled');
        //     $('#btn_reset').removeClass('disabled');
        //     max_size = g_data_pair_only.length;
        //     start = 0;
        //     limit = Math.min(g_data_pair_only.length, limit);
        //     two_way_only = true;
        //     funct_to_load_two_way_pairs(start, limit);
        //     $('#p_table_result_info').html(1 + '-' + limit + '(' + max_size + ')');
        // }
        // /*********************************************************************************************************************************************************************************/


        /*************************************************************TO RESET THE TABLE *************************************************/
        function load_all_icmp_streams() { // to reset the table to original data
            $('#btn_load_two_way_icmp').removeClass('disabled');
            $('#btn_rr_pairs').removeClass('disabled');
            $('#btn_reset').addClass('disabled');
            limit = rows_per_page;
            two_way_only = false;
            rr_pairs_flag = false;
            initialise_stream_display();
            // $('#btn_reset').removeClass('disabled');
        }
        /**********************************************************************************************************************************/


        /***************************************************************TO LOAD NEXT PAGE**********************************************/
        // function load_table_result_next() { //next button functionality
        //     $('#btn_reset').removeClass('disabled');
        //     if (two_way_only == true) {
        //         var next_pairs = limit;
        //     } else {
        //         if (limit != max_size) {
        //             next = limit;
        //         }

        //     }
        //     if (two_way_only == true) {
        //         if (max_size > next_pairs) {
        //             limit = limit + rows_per_page;
        //             limit = Math.min(g_data_pair_only.length, limit);
        //             table_result.empty();
        //             funct_to_load_two_way_pairs(next_pairs, limit);
        //             $('#p_table_result_info').html((next_pairs + 1) + '-' + limit + '(' + max_size + ')');
        //         }
        //     } else if (max_size > next) {
        //         limit = limit + rows_per_page;
        //         limit = Math.min(table_data.length, limit);
        //         table_result.empty();
        //         display_stream_data(next, limit);
        //         $('#p_table_result_info').html((next + 1) + '-' + limit + '(' + max_size + ')');
        //     }
        // }
        /*****************************************************************************************************************************/



        /*********************************TO LOAD PREVIOUS PAGE*******************************************************************/
        // function load_table_result_prev() { //previous button functionality
        //     if (two_way_only == true) {
        //         if ((limit % 100) == 0) {
        //             var prev_two_way = limit - (2 * rows_per_page);
        //             if (prev_two_way >= 0) {
        //                 limit = limit - rows_per_page;
        //             } else {
        //                 prev_two_way = 0;
        //                 limit = Math.min(rows_per_page, limit);
        //             }
        //             table_result.empty();
        //             funct_to_load_two_way_pairs(prev_two_way, limit);
        //             $('#p_table_result_info').html((prev_two_way + 1) + '-' + limit + '(' + max_size + ')');

        //         } else {
        //             var k = limit - rows_per_page;
        //             if (k > 0) {
        //                 var prev_two_way = limit - k;
        //                 if (prev_two_way >= 0) {
        //                     var v = limit - (2 * rows_per_page);
        //                     limit = limit - v;
        //                 } else {
        //                     prev_two_way = 0;
        //                     limit = Math.min(rows_per_page, limit);
        //                 }
        //                 table_result.empty();
        //                 funct_to_load_two_way_pairs(prev_two_way, limit);
        //                 $('#p_table_result_info').html((prev_two_way + 1) + '-' + limit + '(' + max_size + ')');
        //             }

        //         }
        //     }
        //     else if (rr_pairs_flag == true) {
        //         if ((limit % 100) == 0) {
        //             var prev_rr_pair = limit - (2 * rows_per_page);
        //             if (prev_rr_pair >= 0) {
        //                 limit = limit - rows_per_page;
        //             } else {
        //                 prev_rr_pair = 0;
        //                 limit = Math.min(rows_per_page, limit);
        //             }
        //             table_result.empty();
        //             rr_pairs(prev_rr_pair, limit);
        //             $('#p_table_result_info').html((prev_rr_pair + 1) + '-' + limit + '(' + max_size + ')');

        //         } else {
        //             var k = limit - rows_per_page;
        //             if (k > 0) {
        //                 var prev_rr_pair = limit - k;
        //                 if (prev_rr_pair >= 0) {
        //                     var v = limit - (2 * rows_per_page);
        //                     limit = limit - v;
        //                 } else {
        //                     prev_two_way = 0;
        //                     limit = Math.min(rows_per_page, limit);
        //                 }
        //                 table_result.empty();
        //                 rr_pairs(prev_rr_pair, limit);
        //                 $('#p_table_result_info').html((prev_rr_pair + 1) + '-' + limit + '(' + max_size + ')');
        //             }

        //         }
        //     }
        //     else {
        //         if (limit != max_size) {
        //             if (limit % 100 == 0) {
        //                 prev = limit - 2 * rows_per_page;
        //                 if (prev >= 0) {
        //                     limit = limit - rows_per_page;
        //                 } else {
        //                     prev = 0;
        //                     limit = rows_per_page;
        //                 }
        //             }
        //         }

        //         else {
        //             let diff = (limit - next);
        //             limit = limit - diff;
        //             prev = limit - rows_per_page;
        //         }
        //         table_result.empty();
        //         display_stream_data(prev, limit);
        //         $('#p_table_result_info').html((prev + 1) + '-' + limit + '(' + max_size + ')');
        //     }
        // }
        /**********************************************************************************************************************/



        /********************************************* to show the data after a row has been clicked ********************************************/
        function display_seq_data(idx) {
            if (two_way_only == true) {
                if (idx > 0 && idx <= g_data_pair_only.length) {
                    var stream = g_data_pair_only[idx - 1];
                }
            }
            else if (rr_pairs_flag == true) {
                var stream = rr_pairs_data[idx - 1];
            } else {
                if (idx > 0 && idx <= table_data.length) {
                    var stream = table_data[idx - 1];
                }
            }

            $('#table_sequence tbody').empty();

            $('#p_seq_src').html(stream.SrcIp);
            $('#p_seq_dst').html(stream.DstIp);


            /****************************************** To show transaction details************************************************************/
            let totalTransactions = 0;
            let defaultTypes = 0;  //includes ttl exceeded , host unreachable and any other values 

            if (stream.unsuported_or_default != undefined && stream.sequence_array != undefined) {
                totalTransactions = stream.sequence_array.length;
                defaultTypes = stream.unsuported_or_default.length;
                $('#total_transactions').html(totalTransactions + defaultTypes);
            }
            else if (stream.sequence_array != undefined && stream.unsuported_or_default == undefined) {
                totalTransactions = stream.sequence_array.length;
                $('#total_transactions').html(totalTransactions);
            }
            else if (stream.unsuported_or_default != undefined && stream.sequence_array == undefined) {
                totalTransactions = stream.unsuported_or_default.length;
                $('#total_transactions').html(totalTransactions);
            }

            /************************************************************************************************************************************/



            /***********************************************************************************************************************************/
            /* to show the total number of pairs with req and rep == true ,  total unreachable , total timexceeded . request count , reply count
            *************************************************************************************************************************************/
            if (stream.sequence_array != undefined && stream.unsuported_or_default == undefined) {
                showSequenceData(stream.sequence_array);
            }
            else if (stream.sequence_array == undefined && stream.unsuported_or_default != undefined) {
                showUnsupportedData(stream.unsuported_or_default);
            }
            else if (stream.sequence_array != undefined && stream.unsuported_or_default != undefined) {
                showBothSeqDataUnsupportData(stream.sequence_array, stream.unsuported_or_default);
            }

            /************************************************************************************************************************************/
        }

        function showBothSeqDataUnsupportData(seqData, unsupportData) {
            let pairCount = 0; //pair count
            let unreachableCount = 0;
            let timeExceededCount = 0;
            let countReq1 = 0; //request count for request to reply
            let countRep1 = 0; //reply count for request to reply

            for (let i = 0; i < seqData.length; i++) {
                let req = seqData[i].request;
                let rep = seqData[i].reply;

                if (seqData[i].request == true) {
                    countReq1++;
                }
                if (seqData[i].reply == true) {
                    countRep1++;
                }

                if (req == true && rep == true) {
                    count++;
                }
                if (seqData[i].dstUnreachable != false) {
                    unreachableCount++;
                }
                else if (seqData[i].ttlExceeded != false) {
                    timeExceededCount++;
                }
            }


            for (let i = 0; i < unsupportData.length; i++) {
                // let req = unsupportData[i].request;
                // let rep = unsupportData[i].reply;

                // if (unsupportData[i].request == true) {
                //     countReq1++;
                // }
                // if (unsupportData[i].reply == true) {
                //     countRep1++;
                // }

                // if (req == true && rep == true) {
                //     count++;
                // }
                if (unsupportData[i].dstUnreachable != false) {
                    unreachableCount++;
                }
                else if (unsupportData[i].ttlExceeded != false) {
                    timeExceededCount++;

                }
            }

            $('#total_pairs').html(pairCount);
            $('#total_unreachable').html(unreachableCount);
            $('#total_timeexceeded').html(timeExceededCount);
            $('#_request').html(countReq1);
            $('#_reply').html(countRep1);
            $('#min_round_time').html('NA');
            $('#max_round_time').html('NA');
            $('#average_round_time').html('NA');

            $('#table_sequence tbody').empty();
            var str = "";
            for (k = 0; k < seqData.length; k++) {
                var req = seqData[k].request;
                var rep = seqData[k].reply;
                if (req == true && rep == true) {
                    let repTime = seqData[k].repts;
                    let reqTime = seqData[k].reqts;

                    let replyTime = moment(repTime);
                    let rt = replyTime.format("M/D/YYYY H:mm:ss:SSS");

                    let requestTime = moment(reqTime);
                    let st = requestTime.format("M/D/YYYY H:mm:ss:SSS");

                    let diffInTime = moment.duration(repTime - reqTime);

                    str += '<tr class="green">';
                    str += '<td>' + (k + 1) + '</td>';
                    str += '<td>' + seqData[k].sequence_no + '</td>';
                    str += '<td>' + st + '</td>';
                    str += '<td>' + rt + '</td>';
                    str += '<td>' + (diffInTime.hours() > 0 ? diffInTime.hours() + ' hrs ' : '') + (diffInTime.minutes() > 0 ? diffInTime.minutes() + ' mins ' : '') + (diffInTime.seconds() > 0 ? diffInTime.seconds() + ' seconds ' : '') + (diffInTime.milliseconds() + ' msecs') + '</td>';
                }
                else {
                    str += '<tr>';
                    str += '<td>' + (k + 1) + '</td>';
                    str += '<td>' + seqData[k].sequence_no + '</td>';

                    if (req == true) {
                        let req_time = moment(seqData[k].reqts);
                        let r = req_time.format("M/D/YYYY H:mm:ss:SSS");
                        str += '<td>' + r + '</td>';
                    }
                    else {
                        str += '<td>' + "NA" + '</td>';
                    }

                    if (rep == true) {
                        let rep_time = moment(seqData[k].repts);
                        let s = rep_time.format("M/D/YYYY H:mm:ss:SSS");
                        str += '<td>' + s + '</td>';
                    }
                    else {
                        str += '<td>' + "NA" + '</td>';
                    }

                    str += '<td>' + "NA" + '</td>';
                }
                str += '</tr>';
            }
            $('#table_sequence tbody').append(str);


            $('#table_sequence_2 tbody').empty();
            var str_ = "";
            for (k = 0; k < unsupportData.length; k++) {

                str_ += '<tr>';
                str_ += '<td>' + (k + 1) + '</td>';
                str_ += '<td>' + unsupportData[k].sequence_no + '</td>';

                if (unsupportData[k].ttlExceeded == true) {
                    let ttl = moment(unsupportData[k].ttlexcesstime);
                    let ttl_converted = ttl.format("M/D/YYYY H:mm:ss:SSS");
                    str_ += '<td>' + ttl_converted + '</td>';
                }
                else {
                    str_ += '<td>' + "NA" + '</td>';
                }

                if (unsupportData[k].dstUnreachable == true) {
                    let unrc = moment(unsupportData[k].unreachabletime);
                    let unrc_converted = unrc.format("M/D/YYYY H:mm:ss:SSS");
                    str_ += '<td>' + unrc_converted + '</td>';
                }
                else {
                    str_ += '<td>' + "NA" + '</td>';
                }

                str_ += '</tr>';
            }
            $('#table_sequence_2 tbody').append(str_);
        }

        function showUnsupportedData(defaultData) {
            let pairCount = 0; //pair count
            let unreachableCount = 0;
            let timeExceededCount = 0;
            let countReq1 = 0; //request count for request to reply
            let countRep1 = 0; //reply count for request to reply

            for (let i = 0; i < defaultData.length; i++) {

                if (defaultData[i].dstUnreachable != false) {
                    unreachableCount++;
                }
                else if (defaultData[i].ttlExceeded != false) {
                    timeExceededCount++;

                }

            }

            $('#total_pairs').html(pairCount);
            $('#total_unreachable').html(unreachableCount);
            $('#total_timeexceeded').html(timeExceededCount);
            $('#_request').html(countReq1);
            $('#_reply').html(countRep1);
            $('#min_round_time').html('NA');
            $('#max_round_time').html('NA');
            $('#average_round_time').html('NA');



            $('#table_sequence_2 tbody').empty();
            var str = "";
            for (k = 0; k < defaultData.length; k++) {
                str += '<tr>';
                str += '<td>' + (k + 1) + '</td>';
                str += '<td>' + defaultData[k].sequence_no + '</td>';

                if (defaultData[k].ttlExceeded == true) {
                    let ttl = moment(defaultData[k].ttlexcesstime);
                    let ttl_converted = ttl.format("M/D/YYYY H:mm:ss:SSS");
                    str += '<td>' + ttl_converted + '</td>';
                }
                else {
                    str += '<td>' + "NA" + '</td>';
                }

                if (defaultData[k].dstUnreachable == true) {
                    let unrc = moment(defaultData[k].unreachabletime);
                    let unrc_converted = unrc.format("M/D/YYYY H:mm:ss:SSS");
                    str += '<td>' + unrc_converted + '</td>';
                }
                else {
                    str += '<td>' + "NA" + '</td>';
                }

                str += '</tr>';
            }
            $('#table_sequence_2 tbody').append(str);

        }

        function showSequenceData(sequence_data) {
            let count = 0; //pair count
            let unreachableCount = 0;
            let timeExceededCount = 0;
            let countReq1 = 0; //request count for request to reply
            let countRep1 = 0; //reply count for request to reply

            for (let i = 0; i < sequence_data.length; i++) {
                let req = sequence_data[i].request;
                let rep = sequence_data[i].reply;

                if (sequence_data[i].request == true) {
                    countReq1++;
                }
                if (sequence_data[i].reply == true) {
                    countRep1++;
                }

                if (req == true && rep == true) {
                    count++;
                }
                if (sequence_data[i].dstUnreachable != false) {
                    unreachableCount++;
                }
                else if (sequence_data[i].ttlExceeded != false) {
                    timeExceededCount++;

                }

            }

            $('#total_pairs').html(count);
            $('#total_unreachable').html(unreachableCount);
            $('#total_timeexceeded').html(timeExceededCount);
            $('#_request').html(countReq1);
            $('#_reply').html(countRep1);


            let minMax = calculateMinMaxTime(sequence_data);

            let minTime = moment.duration(minMax[0]);
            let maxTime = moment.duration(minMax[1]);
            let avg = moment.duration(minMax[2]);

            $('#min_round_time').html((minTime.hours() > 0 ? minTime.hours() + ' hrs ' : '') + (minTime.minutes() > 0 ? minTime.minutes() + ' mins ' : '') + (minTime.seconds() > 0 ? minTime.seconds() + ' seconds ' : '') + parseInt(minTime.milliseconds()) + ' msecs');
            $('#max_round_time').html((maxTime.hours() > 0 ? maxTime.hours() + ' hrs ' : '') + (maxTime.minutes() > 0 ? maxTime.minutes() + ' mins ' : '') + (maxTime.seconds() > 0 ? maxTime.seconds() + ' seconds ' : '') + parseInt(maxTime.milliseconds()) + ' msecs');

            if (avg == 'NA') {
                $('#average_round_time').html(avg);
            }
            else {
                $('#average_round_time').html((avg.hours() > 0 ? avg.hours() + ' hrs ' : '') + (avg.minutes() > 0 ? avg.minutes() + ' mins ' : '') + (avg.seconds() > 0 ? avg.seconds() + ' seconds ' : '') + parseInt(avg.milliseconds()) + ' msecs');
            }

            $('#table_sequence_2 tbody').empty();
            $('#table_sequence tbody').empty();
            var str = "";
            for (k = 0; k < sequence_data.length; k++) {
                var req = sequence_data[k].request;
                var rep = sequence_data[k].reply;
                if (req == true && rep == true) {
                    let repTime = sequence_data[k].repts;
                    let reqTime = sequence_data[k].reqts;

                    /*EPOCH TIME since January 1st 1970 */
                    let replyTime = moment(repTime);
                    let rt = replyTime.format("M/D/YYYY H:mm:ss:SSS");

                    let requestTime = moment(reqTime);
                    let st = requestTime.format("M/D/YYYY H:mm:ss:SSS");

                    let diffInTime = moment.duration(repTime - reqTime);

                    str += '<tr class="green">';
                    str += '<td>' + (k + 1) + '</td>';
                    str += '<td>' + sequence_data[k].sequence_no + '</td>';
                    str += '<td>' + st + '</td>';
                    str += '<td>' + rt + '</td>';
                    str += '<td>' + (diffInTime.hours() > 0 ? diffInTime.hours() + ' hrs ' : '') + (diffInTime.minutes() > 0 ? diffInTime.minutes() + ' mins ' : '') + (diffInTime.seconds() > 0 ? diffInTime.seconds() + ' seconds ' : '') + (diffInTime.milliseconds() + ' msecs') + '</td>';
                }
                else {
                    // let found = false;
                    // for(let z= 0 ; z < sequence_data.length ; z++)
                    // {
                    //     if(sequence_data[k].sequence_no == sequence_data[z].sequence_no)
                    //     {
                    //         found = true;
                    //     }

                    //     if(found)
                    //     {
                    //         str += '<tr class="red">';
                    //         break;
                    //     }
                    //     else{
                    //         str += '<tr>';
                    //     }
                    // }
                    if (k > 0) {
                        if (sequence_data[k].sequence_no == sequence_data[k - 1].sequence_no) {
                            str += '<tr class="red">';
                       }
                        else {
                            str += '<tr>';
                        }
                    }
                    else
                    {
                        str += '<tr>';
                    }

                    //str += '<tr>';
                    str += '<td>' + (k + 1) + '</td>';
                    str += '<td>' + sequence_data[k].sequence_no + '</td>';

                    if (req == true) {
                        let req_time = moment(sequence_data[k].reqts);
                        let r = req_time.format("M/D/YYYY H:mm:ss:SSS");
                        str += '<td>' + r + '</td>';
                    }
                    else {
                        str += '<td>' + "NA" + '</td>';
                    }

                    if (rep == true) {
                        let rep_time = moment(sequence_data[k].repts);
                        let s = rep_time.format("M/D/YYYY H:mm:ss:SSS");
                        str += '<td>' + s + '</td>';
                    }
                    else {
                        str += '<td>' + "NA" + '</td>';
                    }

                    str += '<td>' + "NA" + '</td>';
                }
                str += '</tr>';
            }
            $('#table_sequence tbody').append(str);
        }


        /*********************CALCULATE MIN , MAX, AVERAGE AND RETURN VALUES IN AN ARRAY******************************************/

        function calculateMinMaxTime(sequenceArray) {
            let timeArray = [];
            let roundTime = [];
            let sequenceArrayLength = sequenceArray.length;
            for (let i = 0; i < sequenceArrayLength; i++) {
                let request = sequenceArray[i].request;
                let reply = sequenceArray[i].reply;

                if (request == true && reply == true) {
                    let requestTime = sequenceArray[i].reqts;
                    let replyTime = sequenceArray[i].repts;

                    let timeDiff = replyTime - requestTime;
                    roundTime.push(timeDiff);
                }
            }


            let minimumTime = Number.MAX_VALUE;
            let maximumTime = 0;
            let total = 0;
            let avg;
            if (roundTime.length > 0) {
                for (let i = 0; i < roundTime.length; i++) {
                    minimumTime = (roundTime[i] < minimumTime) ? roundTime[i] : minimumTime;
                    maximumTime = (roundTime[i] > maximumTime) ? roundTime[i] : maximumTime;
                    total += roundTime[i];
                }
                avg = moment.duration(total / roundTime.length);
            }
            else {
                minimumTime = "NA";
                maximumTime = "NA";
                avg = "NA";
            }

            timeArray[0] = minimumTime;
            timeArray[1] = maximumTime;
            timeArray[2] = avg;

            return timeArray;
        }

        /**************************************************************************************************************************************/


        function display_icmp_database(obj) //for displaying the database file in the select section
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
            ws_command.send("load_selected_icmp_db&" + selected_db.toString());
        }



        //code to search IP address from the table
        function searchipFunction() {
            // Declare variables
            var input, filter, table, tr, td, i;
            input = document.getElementById("myInput");
            filter = input.value.toUpperCase();
            table = document.getElementById("table_result_icmp");
            tr = table.getElementsByTagName("tr");

            // Loop through all table rows, and hide those who don't match the search query
            for (i = 0; i < tr.length; i++) {
                td = tr[i].getElementsByTagName("td")[1];
                if (td) {
                    if (td.innerHTML.toUpperCase().indexOf(filter) > -1) {
                        tr[i].style.display = "";
                    } else {
                        tr[i].style.display = "none";
                    }
                }
            }
        }


        /*****************************************this function is invoked when button LOAD RR PAIRS is being pressed***********************************************/
        function rr_pairs() {

            table_result.empty();

            if (rr_pairs_data.length == 0) {
                Materialize.toast('No RR Pairs!', 4000);
                return;
            }

            if (rr_pairs_data == undefined || !(rr_pairs_data instanceof Array)) return;

            for (i = 0; i < rr_pairs_data.length; ++i) {
                var stream = rr_pairs_data[i];
                var str = '<tr>';
                str += '<td>' + (i + 1) + '</td>';
                str += '<td>' + stream.SrcIp + '</td>';

                if (ipCompare_to_private(stream.SrcIp)) {
                    str += '<td>' + "privateIP" + '</td>';
                }
                else if (stream.src_info == "NA") {
                    str += '<td>' + "NA" + '</td>';
                }
                else {
                    str += '<td>' + stream.src_info.countryName + '</td>';
                }

                str += '<td>' + stream.DstIp + '</td>';

                if (ipCompare_to_private(stream.DstIp)) {
                    str += '<td>' + "privateIP" + '</td>';
                }
                else if (stream.dst_info == "NA") {
                    str += '<td>' + "NA" + '</td>';
                }
                else {
                    str += '<td>' + stream.dst_info.countryName + '</td>';
                }

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

                if (stream.sequence_array != undefined) {
                    str += '<td>';
                    let count = 0;
                    for (let k = 0; k < stream.sequence_array.length; ++k) {
                        totalCount = stream.sequence_array.length;
                        if (stream.sequence_array[k].request == true && stream.sequence_array[k].reply == true) {
                            count += 1;
                        }

                    }
                    str += count + '</td>';

                    let roundTimeArray = [];

                    let minMax = calculateMinMaxTime(stream.sequence_array);

                    str += '<td>';
                    str += minMax[0];
                    str += '</td>';

                    str += '<td>';
                    str += minMax[1];
                    str += '</td>';

                    str += '<td>';
                    str += minMax[2]
                    str += '</td>';

                    str += '</tr>';
                    table_result.append(str);
                }
                else {
                    str += '<td>' + 'NA' + '</td>';
                    str += '<td>' + 'NA' + '</td>';
                    str += '<td>' + 'NA' + '</td>';
                    str += '<td>' + 'NA' + '</td>';
                    str += '</tr>';
                    table_result.append(str);
                }
            }
            $('#table_result_icmp').tablesorter().trigger('update');
            // tableSort();
        }


        /**********************************************************************************************************************************************************/

        function load_all_rr_pairs() {
            $('#btn_rr_pairs').addClass('disabled');
            $('#btn_reset').removeClass('disabled');
            // max_size = rr_pairs_data.length;
            // start = 0;
            // limit = Math.min(rr_pairs_data.length, limit);
            rr_pairs_flag = true;
            rr_pairs();

            //$('#p_table_result_info').html(1 + '-' + limit + '(' + max_size + ')');
        }