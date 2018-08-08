// Declare global variables here
var ws_command;
var ws_messages;
var two_way_only = false;
var g_data;
var g_data_pcap_pairs = [];
var g_data_pcap_evolution_scpc_pairs = [];
var table_result;
//var two_way_table_data;
let next; //used to scroll to next page
var max_size;
let next_pairs;
var start;
let prev;
var global_result_object;
var rows_per_page = 100;
var limit = rows_per_page;
var table_data;
var from_database = false;
var ten_subnet = /^10\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$/;
var one_nine_teo_subnet = /^192\.168\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$/;
var one_seven_2_subnet = /^172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$/;
var reserved_ip = /^100\.(6[4-9]|[7-9][0-9]|1([0-1][0-9]|2[0-7]))\.(0\.(0[ -9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))|([1-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))$/;
var multicast = /^(2(2[4-9]|3[0-9]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$/;

var countryMap = {}; //to store country name with count of packets from that country
var excludePrivateIp = false;
var evolution_scpc = false;


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
    if (evt.data == "pair file saved") {
      $('#btn_save_pairs_info_to_file').removeClass('disabled');
    }
    Materialize.toast(evt.data, 1000);
  }


  table_result = $('#table_result tbody');

  $('#top_nav').load("top_nav.html", function () {
    $('#nav_index').addClass('red lighten-2');
  });




  $('select').material_select();

  /*****************This part is to sort the table which needs to be updated after each next page click**************************************/
  $('#table_result').tablesorter({
    initWidgets: true,
    widgets: ['zebra', 'columns', 'filter']
  });
  /******************************************************************************************************************************************/

//   $("#btn_save_table_csv").click(function(){
//     var table_result = $("#table_result");
//     var html = table_result.querySelector("#file_result table").outerHTML;
//      export_table_to_csv(html, "table.csv");
// }); 

}


function start_analysis() {
  // $('#exclude_private_ip').on('click', function () { //to check if the exclude private ip checkbox is checked or unchecked
  //           if($(this).prop('checked', this.checked))
  //           {
  //               excludePrivateIp = true;
  //           }

  //       });

  if ($('#exclude_private_ip').get(0).checked) {
    excludePrivateIp = true;
  }
  if ($('#evolution_scpc').get(0).checked) {
    evolution_scpc = true;
  }

  $('#btn_start_analysis').addClass('disabled');
  $('#table_result tbody').empty();

  ws_command.send("start_analysis&" + excludePrivateIp + "&" + evolution_scpc);
}

function load_selected_db() {
  $('#btn_load_selected_dbs').addClass('disabled');
  let selected_db = $('#select_db_list :selected').val();
  ws_command.send("load_selected_pcap_db&" + selected_db.toString());
}

function parse_command_reply(data) {
  var obj = JSON.parse(data);
  

  if (obj.type == "result") {
    console.log("Analysis data received.");
    display_analysis_data(obj);
    onLoad_data_refresh();
    $('#btn_start_analysis').removeClass('disabled');
  } else if (obj.type == "load_from_db") {
    console.log("pcap data from database received.");
    from_database = true;
    two_way_only = false;
    display_analysis_data(JSON.parse(obj.data));
    $('#btn_load_selected_dbs').removeClass('disabled');
  } else if (obj.type == "pcap_database") {
    console.log("Full pcap database files received");
    display_pcap_database(obj);
  }
  else if (obj.type == "evolution_result") {
    console.log("Evolution analysis result received");
    display_analysis_data(obj);
    $('#btn_start_analysis').removeClass('disabled');

  }
}


function onLoad_data_refresh() {
  ws_command.onopen = function (evt) {
    ws_command.send("get_pcap_database_all");
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


function display_analysis_data(obj) { //loads data after the analysis is done
  g_data = obj;
  if (evolution_scpc == true) {
    stream_data_file_result_body_evolution_scpc(obj);
    stream_data_pair_result_body_evolution_scpc(obj);
    initialise_stream_display_evolution_scpc();
  } else {
    stream_data_file_result_body(obj);
    stream_data_pair_result_body(obj);
    stream_data_country_count(obj);
    initialise_stream_display();
    set_world_map();
  }

}

/////////////////////////////////FOR EVOLUTION SCPC///////////////////////////////////////////////////
function download_csv(csv, filename) {
  var csvFile;
  var downloadLink;

  // CSV FILE
  csvFile = new Blob([csv], {type: "text/csv"});

  // Download link
  downloadLink = document.createElement("a");

  // File name
  downloadLink.download = filename;

  // We have to create a link to the file
  downloadLink.href = window.URL.createObjectURL(csvFile);

  // Make sure that the link is not displayed
  downloadLink.style.display = "none";

  // Add the link to your DOM
  document.body.appendChild(downloadLink);

  // Lanzamos
  downloadLink.click();
}

function export_table_to_csv(html, filename) {

}

// $('btn_save_table_csv').click(function () {
//   var html = document.querySelector("#file_result table").outerHTML;
// export_table_to_csv(html, "table.csv");
// });

function save_table_csv(){
  // var html = document.querySelector("#file_result table").outerHTML;
  var csv = [];
  var csv_filename = "table.csv";
  
// var rows = $("#table_result tr");
// // document.querySelectorAll("table tr");

//   for (var i = 0; i < rows.length; i++) {
  // var row = [];
  var row_1 = [];
  row_1.push("No.");
  
  row_1.push("Source IP");
  
  row_1.push("Src Country");
  
  row_1.push("Destination IP");
 
  row_1.push("Dst Country");
  
  row_1.push("Source - Destination");
  
  row_1.push("Destination - Source");

  row_1.push("Source - Destination Protocols");
  
  row_1.push("Destination - Source Protocols");
 
  row_1.push("FL Frequencies");
 
  row_1.push("RL Frequencies");
  csv.push(row_1.join(","));

  for(key in table_data){
    var row_test = []
    row_test.push(key);
    
    row_test.push(table_data[key].SrcIp);
   
    row_test.push("NA");
    
    row_test.push(table_data[key].SrcIp);
   
    row_test.push("NA");
    
    if(table_data[key].AtoB instanceof Array){
      
      row_test.push(table_data[key].AtoB[0].Count);
      
    }else{
      row_test.push("0");
      
    }

     if(table_data[key].BtoA instanceof Array){
      row_test.push(table_data[key].BtoA[0].Count);
    
    }else{
      row_test.push("0");
     
    }

    if(table_data[key].AtoB_protocol != undefined){

    }else{
      row_test.push("NA");
      
    }

    if(table_data[key].BtoA_protocol != undefined){

    }else{
      row_test.push("NA");
     
    }

    if(table_data[key].AtoB instanceof Array){
      
      row_test.push(table_data[key].AtoB[0].Freq_Folder);
      
    }else{
      row_test.push("NA");
     
    }

    if(table_data[key].BtoA instanceof Array){
      
      row_test.push(table_data[key].BtoA[0].Freq_Folder);
    
    }else{
      row_test.push("NA");
      
    }

    csv.push(row_test.join(","));
}
//   cols = rows[i].querySelectorAll("td, th");
  
//       for (var j = 0; j < cols.length; j++) 
//           row.push(cols[j].innerText.trim());
      
//   csv.push(row.join(","));		
// }

  // Download CSV
  download_csv(csv.join("\n"), csv_filename);
}

// document.getElementById("btn_save_table_csv").addEventListener("click", function(){
//   document.getElementById("demo").innerHTML = "Hello World";
// });

// document.querySelector('#btn_save_table_csv').on("click", function () {
//   var html = document.querySelector("#file_result table").outerHTML;
// export_table_to_csv(html, "table.csv");
// });



function initialise_stream_display_evolution_scpc() {
  if (g_data == undefined) return;

  table_data = g_data.IPDetails;

  if (from_database == true) {
    limit = rows_per_page;
  }
  //two_way_table_data = g_data.IpDetails;

  var j = 0;
  for (i = 0; i < table_data.length; i++) {
    if ((table_data[i].AtoB instanceof Array) && (table_data[i].BtoA instanceof Array)) {
      g_data_pcap_evolution_scpc_pairs[j] = table_data[i];
      j++;
    }
  }

  max_size = table_data.length;
  start = 0;

  limit = Math.min(table_data.length, limit);

  display_stream_data_evolution_scpc(start, limit);
  $('#p_table_result_info').html(1 + '-' + (limit) + '(' + max_size + ')');
}


function display_stream_data_evolution_scpc(start, limit) {
  table_result.empty();

  if (table_data == undefined || !(table_data instanceof Array)) return;

  for (i = start; i < limit; ++i) {
    var stream = table_data[i];
    var str = '<tr>';
    str += '<td>' + (i + 1) + '</td>';
    str += '<td>' + stream.SrcIp + '</td>';


    if (ipCompare_to_private(stream.SrcIp)) {
      str += '<td>' + "privateIP" + '</td>';
    }
    else {
      str += '<td>' + "NA" + '</td>';
    }


    str += '<td>' + stream.DstIp + '</td>';

    if (ipCompare_to_private(stream.DstIp)) {
      str += '<td>' + "privateIP" + '</td>';
    }
    else {
      str += '<td>' + "NA" + '</td>';
    }




    str += '<td>';
    if (stream.AtoB instanceof Array) {
      for (j = 0; j < stream.AtoB.length; j++) {
        let count = stream.AtoB[j].Count;
        str += count + "<br>";
      }
    }else{
      str += "0" + "<br>";
    }

    str += '</td>';

    str += '<td>';
    if (stream.BtoA instanceof Array) {
      for (j = 0; j < stream.BtoA.length; j++) {
        var count = stream.BtoA[j].Count;
        str += count + "<br>";
      }
    }else{
      str += "0" + "<br>";
    }

    str += '</td>';

    str += '<td>' + "NA" + '</td>';
    str += '<td>' + "NA" + '</td>';

    str += '<td>';
    if (stream.AtoB instanceof Array) {
      for (j = 0; j < stream.AtoB.length; j++) {
        str += stream.AtoB[j].Freq_Folder + "<br>";
      }
    }else{
      str += "NA" + "<br>";
    }
    str += '</td>';

    str += '<td>';
    if (stream.BtoA instanceof Array) {
      for (j = 0; j < stream.BtoA.length; j++) {
        str += stream.BtoA[j].Freq_Folder + "<br>";
      }
    }else{
      str += "NA" + "<br>";
    }
    str += '</td>';

    str += '</tr>';
    table_result.append(str);
  }

  /**********************************updating the table***************************/
  $('#table_result').tablesorter().trigger('update');
  /*******************************************************************************/
}





function stream_data_pair_result_body_evolution_scpc(obj) {
  var myMap = new Map();
  for (i = 0; i < obj.IPDetails.length; i++) {
    var stream = obj.IPDetails[i];

    if (stream.AtoB instanceof Array) {
      for (j = 0; j < stream.AtoB.length; j++) {
        if (myMap.get(stream.AtoB[j].Freq_Folder) == undefined) //if key not found
        {
          var mySet = new Set();
          if (stream.BtoA instanceof Array) {
            for (k = 0; k < stream.BtoA.length; k++) {
              mySet.add(stream.BtoA[k].Freq_Folder);
            }
          }
          myMap.set(stream.AtoB[j].Freq_Folder, mySet);
        }
        else {
          // var MySet = myMap[stream.AtoB[j].Freq_Folder];
          if (stream.BtoA instanceof Array) {
            let newSet = new Set();
            for (k = 0; k < stream.BtoA.length; k++) {
              newSet.add(stream.BtoA[k].Freq_Folder);
            }
            myMap.set(stream.AtoB[j].Freq_Folder, newSet);
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

function stream_data_file_result_body_evolution_scpc(obj) {
  // set d_num_files here from json
  $('#file_result tbody').empty();

  if (obj.data_info) {
    var d_num = obj.data_info.Total_Files_Read;
    document.getElementById("d_num_files").innerHTML = d_num;

    var dtr = '<tr>';
    dtr += '<td>'
    dtr += obj.data_info.filePathFL;
    dtr += '</td>'

    dtr += '<td>'
    dtr += obj.data_info.filePathRL;
    dtr += '</td>'

    dtr += '<td>'
    dtr += obj.data_info.CreatedAt;
    dtr += '</td>'


    if (obj.data_info.Freq_Files != undefined) {
      dtr += '<td>'
      for (j = 0; j < obj.data_info.Freq_Files.length; j++) {
        dtr += obj.data_info.Freq_Files[j].pcapFile + ' (' + obj.data_info.Freq_Files[j].size + ')' + '<br>';
      }
      dtr += '</td>'
    } else {
      dtr += '<td>'
      dtr += "No_files";
      dtr += '</td>'
    }

    if (obj.data_info.RL_Files != undefined) {
      dtr += '<td>'
      for (j = 0; j < obj.data_info.RL_Files.length; j++) {
        dtr += obj.data_info.RL_Files[j].pcapFileRl + ' (' + obj.data_info.RL_Files[j].size + ')' + '<br>';
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


function funct_to_load_two_way_pairs_evolution_scpc(start, limit) // function to load two way data called by load_2_way_streams() function
{
  table_result.empty();
  if (g_data_pcap_evolution_scpc_pairs == undefined || !(g_data_pcap_evolution_scpc_pairs instanceof Array)) return;

  for (i = start; i < limit; ++i) {
    var stream = g_data_pcap_evolution_scpc_pairs[i];

    var pcap_pair_str = '<tr>';
    pcap_pair_str += '<td>' + (i + 1) + '</td>';
    pcap_pair_str += '<td>' + stream.SrcIp + '</td>';

    if (ipCompare_to_private(stream.SrcIp)) {
      pcap_pair_str += '<td>' + "privateIP" + '</td>';
    }
    else {
      pcap_pair_str += '<td>' + "NA" + '</td>';
    }

    pcap_pair_str += '<td>' + stream.DstIp + '</td>';

    if (ipCompare_to_private(stream.DstIp)) {
      pcap_pair_str += '<td>' + "privateIP" + '</td>';
    }
    else {
      pcap_pair_str += '<td>' + "NA" + '</td>';
    }



    pcap_pair_str += '<td>';
    if (stream.AtoB instanceof Array) {
      for (j = 0; j < stream.AtoB.length; j++) {
        let count = stream.AtoB[j].Count;
        pcap_pair_str += count + "<br>";

      }
    }
    pcap_pair_str += '</td>';

    pcap_pair_str += '<td>';
    if (stream.BtoA instanceof Array) {
      for (j = 0; j < stream.BtoA.length; j++) {
        let count = stream.BtoA[j].Count;
        pcap_pair_str += count + "<br>";
      }
    }

    pcap_pair_str += '</td>';

    pcap_pair_str += '<td>' + "NA" + '</td>';
    pcap_pair_str += '<td>' + "NA" + '</td>';

    pcap_pair_str += '<td>';

    if (stream.AtoB instanceof Array) {
      for (j = 0; j < stream.AtoB.length; j++) {
        pcap_pair_str += stream.AtoB[j].Freq_Folder + "<br>";
      }
    }
    pcap_pair_str += '</td>';

    pcap_pair_str += '<td>';
    if (stream.BtoA instanceof Array) {
      for (j = 0; j < stream.BtoA.length; j++) {
        pcap_pair_str += stream.BtoA[j].Freq_Folder + "<br>";
      }
    }
    pcap_pair_str += '</td>';

    pcap_pair_str += '</tr>';
    table_result.append(pcap_pair_str);

  }
  // 
}




/////////////////////////////////////////FOR EVOLUTION SCPC ENDS////////////////////////////////////////////////////////////////


function set_world_map() {
  var country_data = {};

  let color = {};

  color['fillKey'] = 'present';

  // let count = {};

  $('#map_container').empty();

  var map = new Datamap({
    element: document.getElementById('map_container'),
    geographyConfig: {
      highlightBorderColor: '#ff7f50',
      highlightBorderWidth: 3,
      popupTemplate: function (geography, country_data) { return '<div class="hoverinfo">' + geography.properties.name + '</br>Packet Count : ' + country_data.count },
      highlightOnHover: false
    },
    fills: {
      'present': '#1f77b4',
      defaultFill: '#EDDC4E'
    }
  });

  var found = false;
  for (var key in countryMap) {
    var name = key;
    var packetCount = countryMap[key];
    if (name === "United States") {
      name = name + " of America";
    }

    for (i = 0; i < map.worldTopo.objects.world.geometries.length; i++) {

      if (name == map.worldTopo.objects.world.geometries[i].properties.name) {
        country_data[map.worldTopo.objects.world.geometries[i].id] = color;
        country_data[map.worldTopo.objects.world.geometries[i].id]['count'] = packetCount;

        found = true;
        break;
      }
    }

    if (!found)
      console.log(key + ' not found');
    packetCount = null;

  }
  map.updateChoropleth(country_data, { reset: true });//update the map with new data 

}

function stream_data_file_result_body(obj) {
  // set d_num_files here from json
  $('#file_result tbody').empty();

  if (obj.data_info) {
    var d_num = obj.data_info.Total_Files_Read;
    document.getElementById("d_num_files").innerHTML = d_num;

    var dtr = '<tr>';
    dtr += '<td>'
    dtr += obj.data_info.filePathFL;
    dtr += '</td>'

    dtr += '<td>'
    dtr += obj.data_info.filePathRL;
    dtr += '</td>'

    dtr += '<td>'
    dtr += obj.data_info.CreatedAt;
    dtr += '</td>'


    if (obj.data_info.FL_Files != undefined) {
      dtr += '<td>'
      for (j = 0; j < obj.data_info.FL_Files.length; j++) {
        dtr += obj.data_info.FL_Files[j].pcapFileFl + ' (' + obj.data_info.FL_Files[j].size + ')' + '<br>';
      }
      dtr += '</td>'
    } else {
      dtr += '<td>'
      dtr += "No_files";
      dtr += '</td>'
    }

    if (obj.data_info.RL_Files != undefined) {
      dtr += '<td>'
      for (j = 0; j < obj.data_info.RL_Files.length; j++) {
        dtr += obj.data_info.RL_Files[j].pcapFileRl + ' (' + obj.data_info.RL_Files[j].size + ')' + '<br>';
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

function stream_data_pair_result_body(obj) {
  var myMap = new Map();
  for (i = 0; i < obj.IPDetails.length; i++) {
    var stream = obj.IPDetails[i];

    if (stream.folders_AB instanceof Array) {
      for (j = 0; j < stream.folders_AB.length; j++) {
        if (myMap.get(stream.folders_AB[j]) == undefined) //if key not found
        {
          var mySet = new Set();
          if (stream.folders_BA instanceof Array) {
            for (k = 0; k < stream.folders_BA.length; k++) {
              mySet.add(stream.folders_BA[k]);
            }
          }
          myMap.set(stream.folders_AB[j], mySet);
        }
        else {
          var MySet = myMap[stream.folders_AB[j]];
          if (stream.folders_BA instanceof Array) {
            for (k = 0; k < stream.folders_BA.length; k++) {
              mySet.add(stream.folders_BA[k]);
            }
            // myMap.set(stream.folders_AB[j] , mySet);
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

  table_data = g_data.IPDetails;

  if (from_database == true) {
    limit = rows_per_page;
  }
  //two_way_table_data = g_data.IpDetails;

  var j = 0;
  for (i = 0; i < table_data.length; i++) {
    if ((table_data[i].folders_AB instanceof Array) && (table_data[i].folders_BA instanceof Array)) {
      g_data_pcap_pairs[j] = table_data[i];
      j++;
    }
  }

  max_size = table_data.length;
  start = 0;

  limit = Math.min(table_data.length, limit);

  display_stream_data(start, limit);
  $('#p_table_result_info').html(1 + '-' + (limit) + '(' + max_size + ')');
}

function ipCompare_to_private(ip) //to compare src or dst string to check if its private or public
{
  //true == private ; false == public
  if (ten_subnet.test(ip)) {
    return true;
  } else if (one_nine_teo_subnet.test(ip)) {
    return true;
  } else if (one_seven_2_subnet.test(ip)) {
    return true;
  } else if (reserved_ip.test(ip)) {
    return true;
  }
  else if (multicast.test(ip)) {
    return true;
  } else
    return false;

}

function display_stream_data(start, limit) {
  table_result.empty();

  if (table_data == undefined || !(table_data instanceof Array)) return;

  for (i = start; i < limit; ++i) {
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

    str += '<td>' + stream.PacketCount_AB + '</td>';
    str += '<td>' + stream.PacketCount_BA + '</td>';

    str += '<td>';
    if (stream.protocols_AB instanceof Array) {
      for (j = 0; j < stream.protocols_AB.length; j++) {
        var proto = stream.protocols_AB[j];
        if (proto.protocolType != undefined) {
          str += proto.protocolType + ":" + proto.protocolCount + "<br>";
        }
      }
    }

    str += '</td>';

    str += '<td>';
    if (stream.protocols_BA instanceof Array) {
      for (j = 0; j < stream.protocols_BA.length; j++) {
        var proto = stream.protocols_BA[j];
        if (proto.protocolType != undefined) {
          str += proto.protocolType + ":" + proto.protocolCount + "<br>";
        }
      }

    }

    str += '</td>';

    str += '<td>';
    if (stream.folders_AB instanceof Array) {
      for (j = 0; j < stream.folders_AB.length; j++) {
        str += stream.folders_AB[j] + "<br>";
      }
    }
    str += '</td>';

    str += '<td>';
    if (stream.folders_BA instanceof Array) {
      for (j = 0; j < stream.folders_BA.length; j++) {
        str += stream.folders_BA[j] + "<br>";
      }
    }
    str += '</td>';

    str += '</tr>';
    table_result.append(str);
  }

  /**********************************updating the table***************************/
  $('#table_result').tablesorter().trigger('update');
  /*******************************************************************************/
}




function stream_data_country_count(obj) {
  var mySet_country = new Set();

  for (i = 0; i < obj.IPDetails.length; i++) {
    var country_count_stream = obj.IPDetails[i];
    if (country_count_stream.src_info != undefined) {
      //  if (country_count_stream.src_info.countryName != undefined) {
      if (countryMap[country_count_stream.src_info.countryName] != undefined) {
        countryMap[country_count_stream.src_info.countryName]++;
      } else {
        countryMap[country_count_stream.src_info.countryName] = 1;
      }
      //  }

    }
    if (country_count_stream.dst_info != undefined) {
      //  if (country_count_stream.dst_info.countryName != undefined) {
      if (countryMap[country_count_stream.dst_info.countryName] != undefined) {
        countryMap[country_count_stream.dst_info.countryName]++;
      } else {
        countryMap[country_count_stream.dst_info.countryName] = 1;
      }
      //  }
    }
  }


  $('#country_count tbody').empty();
  var country_count_str = "";
  for (var key in countryMap) {
    country_count_str += '<tr>';
    country_count_str += '<td>' + key + '</td>';
    country_count_str += '<td>' + countryMap[key] + '</td>';
    country_count_str += '</tr>';
  }
  $('#country_count tbody').append(country_count_str);
}


function load_table_result_next() {
  $('#btn_reset').removeClass('disabled');
  if (two_way_only == true) {
    if (limit != max_size) {
      next_pairs = limit;
    }
  } else {
    if (limit != max_size) {
      next = limit; //to check if limit is not equal to max_size otherise next will be set to limit which is equal to max_size
    }

  }
  if (two_way_only == true) {
    if (max_size > next_pairs) {
      limit = limit + rows_per_page;
      if (evolution_scpc == true) {
        limit = Math.min(g_data_pcap_evolution_scpc_pairs.length, limit);
        table_result.empty();
        funct_to_load_two_way_pairs_evolution_scpc(next_pairs, limit);
        $('#p_table_result_info').html((next_pairs + 1) + '-' + limit + '(' + max_size + ')');
      } else {
        limit = Math.min(g_data_pcap_pairs.length, limit);
        table_result.empty();
        funct_to_load_two_way_pairs(next_pairs, limit);
        $('#p_table_result_info').html((next_pairs + 1) + '-' + limit + '(' + max_size + ')');
      }

    }
  } else if (max_size > next) {
    limit = limit + rows_per_page;
    limit = Math.min(table_data.length, limit);
    table_result.empty();
    if (evolution_scpc == true) {
      display_stream_data_evolution_scpc(next, limit);
      $('#p_table_result_info').html((next + 1) + '-' + (limit) + '(' + max_size + ')');
    } else {
      display_stream_data(next, limit);
      $('#p_table_result_info').html((next + 1) + '-' + (limit) + '(' + max_size + ')');
    }

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
    } else {
      let diff_two_way = limit - next_pairs;
      limit = limit - diff_two_way;
      prev_two_way = limit - rows_per_page;
    }

    table_result.empty();
    if (evolution_scpc == true) {
      funct_to_load_two_way_pairs_evolution_scpc(prev_two_way, limit);
      $('#p_table_result_info').html((prev_two_way + 1) + '-' + limit + '(' + max_size + ')');
    }
    else {
      funct_to_load_two_way_pairs(prev_two_way, limit);
      $('#p_table_result_info').html((prev_two_way + 1) + '-' + limit + '(' + max_size + ')');
    }

  } else {
    if (limit % 100 == 0) {
      prev = limit - 2 * rows_per_page;
      if (prev >= 0) {
        limit = limit - rows_per_page;
      } else {
        prev = 0;
        limit = rows_per_page;
      }
    }
    else {
      let diff = (limit - next);
      limit = limit - diff;
      prev = limit - rows_per_page;
    }

    table_result.empty();
    if (evolution_scpc == true) {
      display_stream_data_evolution_scpc(prev, limit);
      $('#p_table_result_info').html((prev + 1) + '-' + limit + '(' + max_size + ')');
    } else {
      display_stream_data(prev, limit);
      $('#p_table_result_info').html((prev + 1) + '-' + limit + '(' + max_size + ')');
    }

  }
}

function load_2_way_streams() {
  $('#btn_load_two_way').addClass('disabled');
  $('#btn_reset').removeClass('disabled');
  start = 0;
  two_way_only = true;
  if (evolution_scpc == true) {
    max_size = g_data_pcap_evolution_scpc_pairs.length;
    limit = Math.min(max_size, limit);
    funct_to_load_two_way_pairs_evolution_scpc(start, limit);
    $('#p_table_result_info').html(1 + '-' + limit + '(' + max_size + ')');
  }
  else {
    max_size = g_data_pcap_pairs.length;
    limit = Math.min(max_size, limit);
    funct_to_load_two_way_pairs(start, limit);
    $('#p_table_result_info').html(1 + '-' + limit + '(' + max_size + ')');
  }
}

function funct_to_load_two_way_pairs(start, limit) // function to load two way data called by load_2_way_streams() function
{
  table_result.empty();
  if (g_data_pcap_pairs == undefined || !(g_data_pcap_pairs instanceof Array)) return;

  for (i = start; i < limit; ++i) {
    var stream = g_data_pcap_pairs[i];

    var pcap_pair_str = '<tr>';
    pcap_pair_str += '<td>' + (i + 1) + '</td>';
    pcap_pair_str += '<td>' + stream.SrcIp + '</td>';

    if (ipCompare_to_private(stream.SrcIp)) {
      pcap_pair_str += '<td>' + "privateIP" + '</td>';
    }
    else if (stream.src_info == "NA") {
      pcap_pair_str += '<td>' + "NA" + '</td>';
    }
    else {
      pcap_pair_str += '<td>' + stream.src_info.countryName + '</td>';
    }

    pcap_pair_str += '<td>' + stream.DstIp + '</td>';

    if (ipCompare_to_private(stream.DstIp)) {
      pcap_pair_str += '<td>' + "privateIP" + '</td>';
    }
    else if (stream.dst_info == "NA") {
      pcap_pair_str += '<td>' + "NA" + '</td>';
    }
    else {
      pcap_pair_str += '<td>' + stream.dst_info.countryName + '</td>';
    }

    pcap_pair_str += '<td>' + stream.PacketCount_AB + '</td>';
    pcap_pair_str += '<td>' + stream.PacketCount_BA + '</td>';

    pcap_pair_str += '<td>';
    if (stream.protocols_AB instanceof Array) {
      for (j = 0; j < stream.protocols_AB.length; j++) {
        var proto = stream.protocols_AB[j];
        if (proto.protocolType != undefined) {
          pcap_pair_str += proto.protocolType + ":" + proto.protocolCount + "<br>";
        }
      }
    }
    pcap_pair_str += '</td>';

    pcap_pair_str += '<td>';
    if (stream.protocols_BA instanceof Array) {
      for (j = 0; j < stream.protocols_BA.length; j++) {
        var proto = stream.protocols_BA[j];
        if (proto.protocolType != undefined) {
          pcap_pair_str += proto.protocolType + ":" + proto.protocolCount + "<br>";
        }
      }
    }

    pcap_pair_str += '</td>';

    pcap_pair_str += '<td>';

    if (stream.folders_AB instanceof Array) {
      for (j = 0; j < stream.folders_AB.length; j++) {
        pcap_pair_str += stream.folders_AB[j] + "<br>";
      }
    }
    pcap_pair_str += '</td>';

    pcap_pair_str += '<td>';
    if (stream.folders_BA instanceof Array) {
      for (j = 0; j < stream.folders_BA.length; j++) {
        pcap_pair_str += stream.folders_BA[j] + "<br>";
      }
    }
    pcap_pair_str += '</td>';

    pcap_pair_str += '</tr>';
    table_result.append(pcap_pair_str);

  }
  // 
}

function load_all_streams() {
  $('#btn_load_two_way').removeClass('disabled');
  $('#btn_reset').addClass('disabled');

  start = 0;
  limit = rows_per_page;
  two_way_only = false;
  max_size = table_data.length;
  if (evolution_scpc == true) {
    display_stream_data_evolution_scpc(start, limit);
    $('#p_table_result_info').html(1 + '-' + limit + '(' + max_size + ')');
  } else {
    display_stream_data(start, limit);
    $('#p_table_result_info').html(1 + '-' + limit + '(' + max_size + ')');
  }

}

function display_pcap_database(obj) //for displaying data after loading the json from database
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

//code to search IP address from the table
function searchipFunction() {
  // Declare variables
  var input, filter, table, tr, td, i;
  input = document.getElementById("myInput");
  filter = input.value.toUpperCase();
  table = document.getElementById("table_result");
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

function save_pairs_info_to_file() {
  $('#btn_save_pairs_info_to_file').addClass('disabled');
  ws_command.send("save_pairs_");
}