<?php
/*
Plugin Name: Login Tracker Logs
Plugin URI:
Description: Logs and View successful logins with Country Names of that IP!!! also, enable mail notifications for Unknown IPs, or even DISABLE THEM! 
Version: 1.1
Author: selnomeria
Author URI: http://codesphpjs.blogspot.com
*/
//include_once(dirname(__file__).'/trunk/login-tracker-logs.php');

$newlgs= new Login_Tracker_logs;
class Login_Tracker_logs 
{
	protected $whois_site		= 'http://www.whois.com/whois/';
	
	public function __construct()
	{
	register_activation_hook( __FILE__,  array($this, 'lgs_install'));
	// run it before the headers and cookies are sent
	add_action( 'after_setup_theme', array($this, 'lgs_login_checker'));
	//add page under SETTINGS
	add_action('admin_menu', array($this, 'logintrackss_funcct') ); 
	}
	
	
	public function lgs_install()
	{
		global $wpdb;	$table_name = $wpdb->prefix."tracked_logins";
		$create_table = $wpdb->query("CREATE TABLE IF NOT EXISTS `$table_name` (
			  `id` int(50) NOT NULL AUTO_INCREMENT,
			  `username` varchar(150) CHARACTER SET utf8 NOT NULL,
			  `time` datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
			  `ip` varchar(150) CHARACTER SET utf8 NOT NULL,
			  `country` varchar(250) CHARACTER SET utf8 NOT NULL,
			  `success` varchar(2) CHARACTER SET utf8 NOT NULL,
			  `extra_column2` varchar(400) CHARACTER SET utf8 NOT NULL,
				PRIMARY KEY (`id`),
				UNIQUE KEY `id` (`id`)
			)  ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ; ") or die("error_2345_". mysql_error().$logintracks_tname);
	}

	
	
	
	public function get_remote_data($url, $from_mobile=false , $post_request=false, $post_paramtrs=false )	
	{
		$c = curl_init();
		curl_setopt($c, CURLOPT_URL, $url);
		curl_setopt($c, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)");
		curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($c, CURLOPT_SSL_VERIFYHOST,false);
		curl_setopt($c, CURLOPT_SSL_VERIFYPEER,false);
		curl_setopt($c, CURLOPT_MAXREDIRS, 10);
		curl_setopt($c, CURLOPT_FOLLOWLOCATION, 1);
		curl_setopt($c, CURLOPT_CONNECTTIMEOUT, 9);
		$data = curl_exec($c);
		curl_close($c);
		return $data;
	}
	
	public function allowed_ipss_file()
	{
		return  dirname(__FILE__).'/ALLOWED_IPS.php';
	}


	public function lgs_login_checker() 
	{
		global $wpdb;	$table_name = $wpdb->prefix."tracked_logins";
		$user_ip	= $_SERVER['REMOTE_ADDR'];

			
		//====================only when WP-LOGIN.PAGE is accessed. otherwise, the function will slower all normal page loads=======
		//check if he is disabled
		if (strpos($_SERVER['REQUEST_URI'],'/wp-login.php') !== false )
		{
			//variables for IP validity checking
			$allwd_ips = file_get_contents($this->allowed_ipss_file());
			$settings_for_whiteIPS = get_option('optin_for_white_ipss');
		
			//check if BLOCKED
			if (strpos($allwd_ips,$user_ip) === false)
			{
				if ($settings_for_whiteIPS == 3)
				{
					die("Login is disabled. Your IP is: ".$user_ip);
				}
			}
		}
		
		
		
		
		
		
		if (!empty($_POST['log']) && !empty($_POST['pwd']))
		{
			//variables for IP validity checking
			$allwd_ips = file_get_contents($this->allowed_ipss_file());
			$settings_for_whiteIPS = get_option('optin_for_white_ipss');
		
			$submitted_username = sanitize_text_field(esc_attr($_POST['log']));
			$creds = array();
			$creds['user_login']	= $submitted_username;
			$creds['user_password']	= $_POST['pwd'];
			$creds['remember']		= $_POST['rememberme'];
			$user = wp_signon( $creds, false );
			
			if ( !is_wp_error($user) )
			{
				//INSERT IN DATABASE
				if (get_option('lgs_enable_WHOIS') != 'yes' ) 
				{
					include( dirname(__file__)."/ip_country_data_2014/geoip.inc" );
					$gi = geoip_open(dirname(__file__)."/ip_country_data_2014/GeoIP.dat", GEOIP_STANDARD); 
					$country_name = geoip_country_name_by_addr($gi, $user_ip );
					geoip_close($gi);
					$ip_country = $country_name;
				}
				else
				{
					$got_resultt = $this->get_remote_data($this->whois_site.$user_ip);
					preg_match('/address:(.*?)address:(.*?)address:(.*?)address:(.*?)address:(.*?)phone/si',$got_resultt, $output);
					$ip_country = !empty($output[5]) ?  $output[5].'('.$output[4].')' :  '';
				}
				$insert = $wpdb->query($wpdb->prepare("INSERT INTO $table_name (username, time,ip,country, success) VALUES (%s, %s, %s, %s, %s)", $submitted_username, current_time('mysql'),$user_ip, $ip_country, 1)); 

				//CHECK IP (BLOCK or Send notification)
				if (strpos($allwd_ips,$user_ip) === false)
				{
					if ($settings_for_whiteIPS == 2)
					{
						$siteURL = home_url();
						$adminURL= admin_url('options-general.php?page=lgs-submenu-page');
						
						$admin_mail	= get_option('admin_email');
						$subjectt	="UNKNOWN IP($user_ip) has logged into $siteURL ";
						$full_messag="\r\n\r\n Someone with an IP $user_ip has logged into your site. \r\n\r\n (if you know him, you can add him to whitelist $adminURL";
						// To send HTML mail, the Content-type header must be set
						$headers  = "MIME-Version: 1.0\r\n";
						$headers .= "Content-type: text/html\r\n";
						$headers .= "From: LOGGER GUARD <noreply@noreply.com>\r\nReply-To: noreply@noreply.com\r\nX-Mailer: PHP/".phpversion();


						if ($_SERVER['HTTP_HOST'] !== 'localhost')
						{
							$result = mail( $admin_mail ,$subjectt, $full_messag ,$headersss) ? "okkk" : "problemm";
							//file_put_contents(dirname(__file__).'/aaaa.txt',$result);
						}
					}
				}
			}
		}
	}



	public function logintrackss_funcct(){	add_submenu_page('options-general.php','LOGIN Tracks','LOGIN Tracks', 'manage_options' ,'lgs-submenu-page', array($this, 'lgs_page_callback') );}
	//output of page
	public function lgs_page_callback()
	{
		global $wpdb;	$table_name = $wpdb->prefix . "tracked_logins";
		//if records cleared
		if ($_POST['logintracks_clear']=='true') 
		{
			$wpdb->get_results("DELETE FROM ".$table_name." WHERE success='0' OR success='1'");
		}
		//if changed whois
		if (!empty($_POST['country_detct'])) 
		{
			update_option('lgs_enable_WHOIS',$_POST['country_detct']);
		}

		
		//get values
		$results = $wpdb->get_results("SELECT username,time,UNIX_TIMESTAMP(time) as timestamp,IP,country,success FROM ".$table_name." ORDER BY time DESC");
		
		
		?>
		<style>
		.my_login_tracks tr.succeed{ background-color:#A6FBA6;}
		.my_login_tracks tr.failed{ background-color:#FFC8BF;}
		</style>
		
		<div class="my_login_tracks">
			<h2>All logins:</h2>
			<table class="widefat" cellpadding="3" cellspacing="3"><tr><th>Username</th><th>Time</th><th>IP</th><th>COUNTRY (<a href="javascript:alert('This is just an approximate country name. To view the full info for a particular IP, then in this column, click that COUNTRY NAME and you will be redirected to the WHOIS WEBSITE, where you will see the FULL INFORMATION of that IP.');">Read THIS!!</a>)</th><th>Succeed</th></tr>
			<?php
			if ($results){foreach ($results as $e) {
						if(!empty($e->country))
							 {$countryyy =  '<a href="'. $this->whois_site . $e->IP.'" target="_blank">'.$e->country.'</a>';}
						else {$countryyy =  '<a href="'. $this->whois_site . $e->IP.'" target="_blank">problem_54_from_plugin</a>';}
		
					echo '<tr class="succeed"><td>'.$e->username.'</td><td>'.$e->time.'</td><td>'.$e->IP.'</td><td>'.$countryyy.'</td><td>succeed<td></tr>';
				}
			}
			?>
			</table>
			
			
			<!-- clear records -->
			<form method="post" action="">
					<input type="hidden" name="logintracks_clear" value="true"/>
					<input type="submit" name="logintracks_submit" value="Clean login data"/>
			</form>
			<!-- ###clear records### -->		
			
			
			
			
			
			
			<!-- ENABLE/DISABLE OPTIONS -->
			<?php
			//IF whitelist updated
			if (!empty($_POST['whitelist_ips'])) 
			{
				update_option('optin_for_white_ipss',$_POST['whitelist_ips']);
				file_put_contents($this->allowed_ipss_file(),'<?php '.$_POST['white_IPS']);
			}
		
			$allowed_ips 	= str_replace('<?php ','', file_get_contents($this->allowed_ipss_file()) );
			$whiteip_answer	= get_option('optin_for_white_ipss');
			$d1 = $whiteip_answer == 1 ? "checked" : '';
			$d2 = $whiteip_answer == 2 ? "checked" : '';
			$d3 = $whiteip_answer == 3 ? "checked" : '';
			?>
			<br/><br/>	
			<form method="post" action="">
				<p class="submit">
					<!--
					<b style="font-size:1.2em;">Turn on City Detection too?</b>  <a href="javascript:alert('If this is disabled, then you will see only COUNTRY NAME of visitor, and you have to click that, and you will see full report for that IP. However, you can ENABLE this option, and then you will see CITY name too (along with COUNTRY NAME), but that process prolongs the log-in process by 3 seconds. ');">read more!!</a> 
					<?php if (get_option('lgs_enable_WHOIS')=='yes') {$enab='checked';$disab='';} else{$enab='';$disab='checked';} ?>
					<br/>
					<input type="radio" name="country_detct" value="yes" <?php echo $enab;?>  />ENABLE
					<input type="radio" name="country_detct" value="no"  <?php echo $disab;?> />DISABLE
					<br/>
					<br/>
					-->
					
					
					<div class="white_list_ipps" style="background-color: #1EE41E;padding: 5px;float: left; margin:0 0 0 20%;">
						IP WHITELISTING setting: (<a href="javascript:alert('If this option will be enabled, then, in the field,you can enter the confident IPs (separated by comma). \r\n\r\n  You can choose:\r\n1) get MAIL NOTIFICATION (at <?php echo get_option('admin_email');?>, changeable from Settings>General. But on localhost mail doesnt work) when anyone logins, whose IP is not in this list. \r\n2) Block anyone to access LOGIN page at all [whose IP is not in the list]. \r\r\n(DONT FORGET TO INSERT YOUR IP TOO! HOWEVER,IF YOU BLOCK YOURSELF,enter FTP and add your IP into this file: wp-content/plugins/<?php echo basename(dirname(__file__));?>/ALLOWED_IPS)\r\n');">read more!!</a>):
						&nbsp;&nbsp;&nbsp;&nbsp;
						&nbsp;OFF<input onclick="lg_radiod();" type="radio" name="whitelist_ips" value="1" <?php echo $d1;?> />
						&nbsp;Mail notification	<input onclick="lg_radiod();" type="radio" name="whitelist_ips" value="2" <?php echo $d2;?> />
						&nbsp;Block anyone, except them<input onclick="lg_radiod();" type="radio" name="whitelist_ips" value="3" <?php echo $d3;?> />
						<br/>
						
						<div id="DIV_whiteipieldd">
							<input id="whiteips_fieldd" type="text" name="white_IPS" value="<?php echo $allowed_ips;?>" style="width:100%;" /> 						(your IP is <b style="color:red;"><?php echo $_SERVER['REMOTE_ADDR'];?></b>)
						</div>
						
						<script type="text/javascript">
						function lg_radiod()
						{
							var valllue = document.querySelector('input[name="whitelist_ips"]:checked').value;
							var DIVipfieldd = document.getElementById("DIV_whiteipieldd");

							if(valllue != "1")	{DIVipfieldd.style.opacity = "1";}
							else				{DIVipfieldd.style.opacity = "0.3";	}
						}
						lg_radiod();
						</script>
					</div>

					<br/><div style="clear:both;"></div>
					<input type="submit"  value="SAVE"/>
				</p> 
			</form>
			
			
			
			
			<br/><br/>

			<div class="">
			-This plugin is good with <b>login attempt blockers</b>, like "Brute force login protection" or "Login Protection" 
			<br/>-(To allow access to WP-LOGIN only to selected IP's, then see - http://codesphpjs.blogspot.com/2014/09/allow-wp-login-only-to-specific-ips.html )
		
			</div>
		</div>
		<?php
	}
}	
?>