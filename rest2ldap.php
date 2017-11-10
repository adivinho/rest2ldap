<?php

$configs = include('rest2ldap.config.php');

// ==================== REST =======================
        $api_url  = "https://".$configs['api_host'].":".$configs['api_port']."/rest";

        # for self-signed certificates
        $verify_hostname = false;
        $post_data = array(
        	'params' => json_encode(array('password' => $configs['api_password'],
                			      'user' => $configs['api_login'])),
                );
	echo "REST => URL: " . $api_url . '/Session/login' . "\n";

        $curl = curl_init();
        curl_setopt_array($curl,
               		array(//CURLOPT_VERBOSE => true,
                        	CURLOPT_URL => $api_url . '/Session/login',
                        	CURLOPT_SSL_VERIFYPEER => $verify_hostname,
                        	CURLOPT_SSL_VERIFYHOST => $verify_hostname,
                        	CURLOPT_RETURNTRANSFER => true,
                        	CURLOPT_POST => true,
                        	CURLOPT_POSTFIELDS => http_build_query($post_data),
                        )
                );

        $reply = curl_exec($curl);

        if(!$reply) {
        	echo curl_error($curl)."\n!";
                curl_close($curl);
                return -1;
        }
        else {
                $data = json_decode($reply);
                if(isset($data->{"faultcode"}))
                        {
                                printf("Caught exception: faultcode=" . $data->{"faultcode"} . ", faultstring=" . $data->{"faultstring"} ."\n");
                                return -1;
                        }
                        else {
                                $session_id = $data->{'session_id'};
                                printf("REST => Session = $session_id\n");
                        }
        }


        $GetCustomerListRequest = array(
                'offset' => 0,
                'limit' => 0, 
        );

        $post_data = array(
                'auth_info' => json_encode(array('session_id' => $session_id)),
                'params' => json_encode( $GetCustomerListRequest ),
        );

        curl_setopt_array($curl,
                        array(
                        CURLOPT_URL => $api_url . '/Customer/get_customer_list',
                        CURLOPT_SSL_VERIFYPEER => $verify_hostname,
                        CURLOPT_SSL_VERIFYHOST => $verify_hostname,
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_POST => true,
                        CURLOPT_POSTFIELDS => http_build_query($post_data),
                        )
        );

        $reply = curl_exec($curl);
        if(!$reply) {
                echo curl_error($curl);
                curl_close($curl);
                exit;
        }

        $customers = json_decode($reply);
	echo "REST => Has been located ".count($customers->customer_list)." customers.\n";
	if ($configs['debug']) {
        	foreach ($customers->customer_list as $customer) {
               		printf("%s: %s, %s\n", $customer->login, $customer->name, $customer->email);
        	}
	}
        curl_close($curl);


// ==================== LDAP ======================
function myldap_delete($ds,$dn,$recursive=false){
    if($recursive == false){
        return(ldap_delete($ds,$dn));
    }else{
        //searching for sub entries
        $sr=ldap_list($ds,$dn,"ObjectClass=*",array(""));
        $info = ldap_get_entries($ds, $sr);
        for($i=0;$i<$info['count'];$i++){
            //deleting recursively sub entries
            $result=myldap_delete($ds,$info[$i]['dn'],$recursive);
            if(!$result){
                //return result code, if delete fails
                return($result);
            }
        }
        return(ldap_delete($ds,$dn));
    }
}	
	

// Connecting to LDAP
	$ds = ldap_connect($configs['ldap_host'], $configs['ldap_port']) or die("LDAP => Could not connect to ".$config['ldap_host']);
	ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
	if ($ds) {
        	$r = ldap_bind($ds,$configs['ldap_admin'],$configs['ldap_password']);
		if ($r) {
        		echo "\nLDAP => ".$configs['ldap_host'].":".$configs['ldap_port']." bind successful...\n";

			echo "LDAP => Found ";
			$result = ldap_search($ds,$configs['ldap_tree'], "(cn=".$configs['ldap_commonName'].")") or die ("Error in search query: ".ldap_error($ds));

// Get all data
 			$data = ldap_get_entries($ds, $result);
			echo count($data)." records for common name - ".$configs['ldap_commonName'].".\n";
			if ($configs['debug']) {print_r($data);}

			echo "LDAP => Dropping all records ...\n";
   			myldap_delete($ds,$configs['ldap_tree'],true); 
			
			ldap_add($ds, $configs['ldap_tree'], array(
    					'ou' => $configs['ldap_organizationUnit'],
    					'objectClass' => 'organizationalUnit'
			));
			echo "LDAP => Added new organization unit (ou) -> ".$configs['ldap_organizationUnit']." ...\n";

//Add an entry
		        $i=0;	
		  	echo "LDAP => Going to add new records ... \n";	
        		foreach ($customers->customer_list as $customer) {
				$cn = $customer->login ?: "login" ;   // set a default value if no login is assigned
				$info["sn"] = filter_var($customer->name, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_HIGH | FILTER_FLAG_STRIP_LOW);
				$info["cn"] = $cn;
				$info["mail"] = $customer->email;
				$info["objectClass"] = "inetOrgPerson";
				$r = ldap_add($ds,"cn=$cn,".$configs['ldap_tree'],$info);
				$i++;
			}
			echo "LDAP => Done. New $i records have been added ...\n";
		}
		else {
        		echo "LDAP => LDAP bind failed...";
		}

		ldap_unbind($ds);
	}
?>
