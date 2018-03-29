<?php

$domain ="bitchk.com";
//subdomain e.g. name.domain.com 
$number_of_records = 20;
//maximum n A records with $name... 10 recommended 
$user = "etra@etra.kr";
//user name
$key = "0a3b6e12f286eea46a3883c9020b0bc5ba7d1";
//key for cloudflare api found in account settings
//absolute path to dnsseed.dump in the nubits-seeder root directory 

$args = getopt("p:n:s:");
$name = $args[n];
$symbol = $args[s];
$port = $args[p];
elog($port ,$name,$symbol);
if(!$port || !$name ||!$symbol ) {
	printf("\nneed args  -p=$port -n=$name -s=$symbol \n");
	exit(0);
}
$seed_dump = "/Users/user/dev/blockchain/yangcoin/bitcoin-seeder/$symbol.dnsseed.dump";

if (! function_exists('array_column')) {
    function array_column(array $input, $columnKey, $indexKey = null) {
        $array = array();
        foreach ($input as $value) {
            if ( !array_key_exists($columnKey, $value)) {
                trigger_error("Key \"$columnKey\" does not exist in array");
                return false;
            }
            if (is_null($indexKey)) {
                $array[] = $value[$columnKey];
            }
            else {
                if ( !array_key_exists($indexKey, $value)) {
                    trigger_error("Key \"$indexKey\" does not exist in array");
                    return false;
                }
                if ( ! is_scalar($value[$indexKey])) {
                    trigger_error("Key \"$indexKey\" does not contain scalar value");
                    return false;
                }
                $array[$value[$indexKey]] = $value[$columnKey];
            }
        }
        return $array;
    }
}
/*
######################################################################################################
				The magic starts here - Don't alter anything below, unless you know what you're doing
############################################################################################################
*/

error_reporting(E_ERROR | E_WARNING | E_PARSE);

include_once("class_cloudflare.php");
//include the cloudflare php API by vexxhost

$type = "A";
//set A records only
$i6 = 0;
//counter
$i5 = 0;
//counter
$i4 = 0;
//counter
$i3 = 0;
//counter
$i2 = 1;
//counter, 1 (line 0 is a header)
$i = 0;
//counter
$offset = 0;
// $ips_used = 0;
//
$i_offset = 0;
//
$end = false;
//
$ip_array=array();
$dns_zone_array=array();
$difference = 0;

if (!file_exists($seed_dump))
{
	echo "Didn't find seed_dump at $seed_dump\n";
	return ;
}

$cf = new cloudflare_api($user, $key);
$response_object = $cf->rec_load_all($domain);
//ALL dns entries of domain
$response_json=json_encode($response_object);
//make objects to JSON
$response_array=json_decode($response_json, true);
//make JSON to array, thanks php

if(isset($response_array["err_code"])){
	if($response_array["err_code"]=="E_UNAUTH"){
		echo "Auth failed, check your email and key!";
	}
}

//write IPs into array 
$ip_raw = file($seed_dump);
//read seed_dump into array
$ip_numbers_in_file = count($ip_raw);

while ($i2 < $ip_numbers_in_file) {
	$ip_array_line = $ip_raw[$i2];
	// elog($ip_array_line);
	//r	ead line 
	$ip_array_split = explode(":",$ip_array_line);
	//e	xplode string at ":"
	$ip = $ip_array_split[0];
	
	// 	[0] is the ip address of the line
	
	$pos = strpos($ip_array_split[1], $port);
	//p	osition of 7890
	$bool_pos=is_bool($pos);
	//c	ustom ports (!= 7890) not allowed.
	if (!$bool_pos) {
		$ip_array_split = str_replace($port, "", $ip_array_split[1]);
		//r		emove port
		$ip_array_split = trim($ip_array_split);
		//r		emove spaces at the start
		$ip_array_split = substr($ip_array_split,0,1);
		//g		et first charakter == the GOOD parameter in the dump file /
		$good =  $ip_array_split;
		$ip_array_while = array(
			'ip' => $ip,
			'good' => $good	);
		
		if ($good==1){
			array_push($ip_array, $ip_array_while);
		}
	}
	$i2++;
	
}

// how many ips in list? are ips available? 
$ip_array_available = count ($ip_array);
if ($ip_array_available>0) {
	$ips_available=true;
}
else {
	$ips_available=false;
}

//check for number of CF $name.$domain entries

$number_of_name_domain_records = count($response_array["response"]["recs"]["objs"]);
//count dns entries with $name.$domain
$entries=0;
//entry counter


while ($i3 < $number_of_name_domain_records)			{
	if($response_array["response"]["recs"]["objs"][$i3]["name"] == "$name.$domain" && $response_array["response"]["recs"]["objs"][$i3]["type"]==$type){
		$entries++;
		$id_zone=$response_array["response"]["recs"]["objs"][$i3]["rec_id"];
		$ip_zone=$response_array["response"]["recs"]["objs"][$i3]["content"];
		$dns_zone_array_while = array( 
			'id' => $id_zone,
			'ip' => $ip_zone	
		);
		array_push($dns_zone_array, $dns_zone_array_while);
	}
	$i3++;
}

//create needed entries if $entries differs from $number_of_records (initial create of zone file)
if($number_of_records<=$entries){
	$difference=$number_of_records-$entries;
}

if($entries<$number_of_records){
	$difference=$number_of_records-$entries;
}

if($number_of_records>$ip_array_available){
	$difference=$number_of_records-$entries-($number_of_records-$ip_array_available);
}

while($i4 < $difference)		{
	$ip_new=$ip_array[$i5]["ip"];
	$good_new=$ip_array[$i5]["good"];
	if ($good_new == 1) {
		$content_new=$ip_new;
		$write_new = $cf->rec_new($domain, $type, $name, $content_new);
	}
	
	//e	rror handling if IP is already in table
	$new_response_array=get_object_vars($write_new);
	$new_response_array_retry=$new_response_array;
	
	while($new_response_array_retry["msg"]=="The record already exists." && $end==false)
										{
		$i5++;
		//move file pointer +1
		$ip_new_retry=$ip_array[$i5]["ip"];
		$good_new_retry=$ip_array[$i5]["good"];
		
		if ($good_new_retry == 1){
			//only re-write the dns entry if good == 1
			$content_new_retry=$ip_new_retry;
			$write_new_retry = $cf->rec_new($domain, $type, $name, $content_new_retry);
		}
		else {
			//seems like no more good ips are available 
			$end=true;
		}
		$new_response_array_retry=get_object_vars($write_new_retry);
		
	}
	$i5++;
	//move file pointer!		
	$i4++;
	//check next missing element
}

//to many entries? delete!
elog("diff $difference");
while($difference < 0){
	$diff_rev=($difference*-1)+$offset;
	$id_diff=$response_array["response"]["recs"]["objs"][$diff_rev]["rec_id"];
	
	if($response_array["response"]["recs"]["objs"][$diff_rev]["type"]==$type && $response_array["response"]["recs"]["objs"][$diff_rev]["name"] == "$name.$domain"){
		elog("delete $domain, $id_diff");
		$delete=$cf->delete_dns_record($domain, $id_diff);
		$difference++;
	}
	else {
		$offset++;
	}
}

//make CF edits

while ($i<$entries){
	$end = false;
	//r	eset end
	$id_entry=$dns_zone_array[$i]["id"];
	$ip_entry=$dns_zone_array[$i]["ip"];
	// elog($ip_entry ,$ip_array);
	$hit=array_search($ip_entry, array_column($ip_array, 'ip'));
	//s	earch for dns zone rec ip in ip_array tale
	
	if(is_numeric($hit) && $hit>=0){  //we have a hit

		//do nothing, it's good. 
		}
		else { ///we don't have a hit, the IP in the dns zone rec is not in the current good ip list and needs to be altered
				//f		ind IP that is in good ip list but not in the current dns zone rec
		
		while($end==false){
			$ip_search=$ip_array[$i6]["ip"];
			//get  $i6 in ip list ($i6 will start at 0 and will be incremented on fail)
			$hit_search_dns=array_search($ip_search, array_column($dns_zone_array, 'ip'));
			//search that IP in DNS array
			
			if ($hit_search_dns == false){ //boolean false could also mean it hit entry 0 here
				$dns_bool=is_bool($hit_search_dns);
				//so we check if it's a real bool 
				if ($dns_bool){ //it's a bool and it is false? we have found a IP in the good ip list which is not in the DNS array!
					$write_edit = $cf->rec_edit($domain, $type, $id_entry, $name, $ip_search);
					//w					rite it
					$end = true;
					//s					top searching
				}
				
			}
			
			if($i6>$ip_array_available){ 
				$end = true;
				// 				no more IPs available
			}
			$i6++;
			//k			eep looking for ip
			
		}
	}
	$i++;
}

function elog($arg, $arg1 = null, $tracePrint = true, $web = false) {
	$trace = debug_backtrace ();
	
	$traceLog = '';
	if ($tracePrint) {
		foreach ( array_reverse ( $trace ) as $result ) {
			$traceLog .= $result ['file'] . ':' . $result ['line'] . "\n\t\t";
		}
	}
	$var1 = is_string ( $arg ) ? $arg : var_export ( $arg, true );
	$var2 = isset ( $arg1 ) ? (is_string ( $arg1 ) ? $arg1 : var_export ( $arg1, true )) : null;
	if (isset ( $var2 ))
		$var2 = "::" . $var2;
	if ($web) {
		echo "<pre>" . $traceLog . "=> " . $var1 . $var2 . "</pre>";
	}
	else
		error_log ( $traceLog . "=> " . $var1 . $var2 );
}
?>