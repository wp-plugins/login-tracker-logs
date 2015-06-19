<?php
/*
Plugin Name: Login Restrict Logs
Plugin URI:
Description: Track logins (username + IP + COUNTRY/CITY );  Allow login only to specific IPs;   Also, send nofitication to admin, when unknown user logins. (P.S.  OTHER MUST-HAVE PLUGINS FOR EVERYONE: http://bitly.com/MWPLUGINS  )
Version: 1.44
Author: selnomeria
*/
if ( ! defined( 'ABSPATH' ) ) exit; //Exit if accessed directly



	
$newlgs= new Login_Restrict_logs;
class Login_Restrict_logs {
	protected $whois_site	='http://www.whois.com/whois/';
	protected $StartSYMBOL	='<?php ZZZ //';
	public $Allow_ips_file	='ALLOWED_IPs_FOR_WP_LOGIN.php';
	public $plugin_pageslug	='lgs-submenu-page';
	
	public function __construct()	{
		add_action( 'activated_plugin', array($this, 'activat_redirect'));
		register_activation_hook( __FILE__,  array($this, 'lgs_install'));
		register_deactivation_hook( __FILE__,  array($this, 'lgs_uninstall'));
		// run it before the headers and cookies are sent
		add_action( 'after_setup_theme', array($this, 'lgs_login_checker'));
		//add page under SETTINGS
		add_action('admin_menu', array($this, 'logintrackss_funcct') ); 
		add_action('init', array($this, 'logintrackss_checkip') ); 
	}
	public function activat_redirect( $plugin ) { if( $plugin == plugin_basename( __FILE__ ) ){ exit( wp_redirect(admin_url( 'admin.php?page='.$this->plugin_pageslug)) ); } }
	public function lgs_install(){	
		update_option('whitelist_ips',1); update_option('lgs_enable_WHOIS','no');
		foreach (get_editable_roles() as $key=>$name){	if (!get_option('lrl__Disallow_'.$key)) {update_option('lrl__Disallow_'.$key, 'yes');}    }
				
		
		global $wpdb;	$table_name = $wpdb->prefix."restrictor_logins";
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
			)  ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ; ") or die("error_2345_". $wpdb->print_error());
		//old_version updating
		$new_dir =ABSPATH.'wp-content/ALLOWED_IP/'.$this->site_nm().'/'; 
		$old_dir =ABSPATH.'ALLOWED_IP/'.str_replace('www.','', $_SERVER['HTTP_HOST']).'/';
			if (file_exists($old_dir.$this->Allow_ips_file)) {@mkdir($new_dir, 0777); @rename($old_dir.$this->Allow_ips_file,$new_dir.$this->Allow_ips_file);@rmdir($old_dir);} 
		$old_dir = ABSPATH.'wp-content/ALLOWED_IP/'.str_replace('www.','', $_SERVER['HTTP_HOST']).'/';
			if (file_exists($old_dir.$this->Allow_ips_file)) {@mkdir($new_dir, 0777); @rename($old_dir.$this->Allow_ips_file,$new_dir.$this->Allow_ips_file);@rmdir($old_dir);} 
	}
	
	public function lgs_uninstall()	{        }			//unlink($this->allowed_ipss_file());
	
	public function site_nm()		{   return preg_replace('/\W/si','_',str_replace('://www.','://', home_url()) );     }	
	public function validate_pageload($value, $action_name){
		if ( !isset($value) || !wp_verify_nonce($value, $action_name) ) {  die("not allowed - error473 (LoginRestrict plugin)"); }
	}	
	public function get_remote_data($url, $from_mobile=false , $post_request=false, $post_paramtrs=false )	{
		$c = curl_init();
		curl_setopt($c, CURLOPT_URL, $url);
		curl_setopt($c, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)");
		curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);		curl_setopt($c, CURLOPT_SSL_VERIFYHOST,false);	curl_setopt($c, CURLOPT_SSL_VERIFYPEER,false);
		curl_setopt($c, CURLOPT_MAXREDIRS, 10);			curl_setopt($c, CURLOPT_FOLLOWLOCATION, 1);		curl_setopt($c, CURLOPT_CONNECTTIMEOUT, 9);
		$data = curl_exec($c);							curl_close($c);		return $data;
	}
	public function allowed_ipss_file() 	{
		
		//file path
		$pt_folder = ABSPATH.'/wp-content/ALLOWED_IP/'. $this->site_nm();	if(!file_exists($pt_folder)){mkdir($pt_folder, 0755, true);}
		$file = $pt_folder .'/'.$this->Allow_ips_file;				
				if(!file_exists($file))		{
						//initial values
						$bakcup_of_ipfile = get_option("backup_ips_".$this->plugin_pageslug.'___'. $this->site_nm() );
					file_put_contents($file, (!empty($bakcup_of_ipfile)?  $bakcup_of_ipfile : $this->StartSYMBOL. '101.101.101.101 (its James, my friend)|||102.102.102.102(its my pc),|||'.$_SERVER['REMOTE_ADDR'].'(my another pc2)||| and so on...') );
				}
		return $file;
	}

	public function logintrackss_checkip(){
		if(is_admin()){
			if (is_user_logged_in()){
				require_once(ABSPATH . 'wp-includes/pluggable.php'); $usID= get_current_user_id();		$user_info= get_userdata($usID);
				$this->checkDef($user_info->user_login);
			}
		}
	}
	
	public function checkDef($submitted_username){		
		//check if BLOCKED
		$allwd_ips = file_get_contents($this->allowed_ipss_file());
		if (get_option('optin_for_white_ipss') == 3){
			if (stripos($submitted_username,'@')!==false) {$userf=get_user_by( 'email',$submitted_username);}	
			if (empty($userf)){ $userf=get_user_by( 'login', $submitted_username );}

			if ( get_option('lrl__Disallow_'.$userf->roles[0]) != 'no' ){
					$IP = $_SERVER['REMOTE_ADDR'];  $IPx= preg_replace('/(.*?)\.(.*?)\.(.*?)\.(.*)/si','$1.$2.$3.'.'*', $_SERVER['REMOTE_ADDR']);
				if (stripos($allwd_ips, $IP ) === false  &&   stripos($allwd_ips,  $IPx) === false  ){ 
					die('Login is disabled for unknown visitors(<span style="font-size:0.8em;font-style:italic;">from /WP-CONTENT---ALLOWED-IP/</span>). Your IP is: '. $_SERVER['REMOTE_ADDR']);
				}
			}
		}
	}
	
	
	
	
	
	
	public function lgs_login_checker() {
		//====================only when WP-LOGIN.PAGE is accessed. otherwise, the function will slower all normal page loads=======
		//check if he is disabled
		/*if (stripos($_SERVER['REQUEST_URI'],'/wp-login.php') !== false || in_array( $GLOBALS['pagenow'], array( 'wp-login.php', 'wp-register.php' ) )  )	{
			
		}*/
		
		if (!empty($_POST['log']) && !empty($_POST['pwd']))	{
			global $wpdb;	$table_name = $wpdb->prefix."restrictor_logins";
			//variables for IP validity checking
			$user_ip	= $_SERVER['REMOTE_ADDR'];
			$creds = array();		  $submitted_username = sanitize_text_field(esc_attr($_POST['log']));
			$creds['user_login']	= $submitted_username;
			$creds['user_password']	= $_POST['pwd'];
			$creds['remember']		= $_POST['rememberme'];
		
			$this->checkDef($submitted_username);
		
			$user = wp_signon( $creds, false );
			
			
			//=================INSERT IN DATABASE===============
			if ( !is_wp_error($user) ){
				if (get_option('lgs_enable_WHOIS') != 'yes' ){		//if user has enabled remote whois
					include( dirname(__file__)."/ip_country_data_2014/sample-test.php" ); $ip_country = $country_name;
				}
				else{
					$got_resultt = $this->get_remote_data($this->whois_site.$user_ip);
					preg_match('/address:(.*?)address:(.*?)address:(.*?)address:(.*?)address:(.*?)phone/si',$got_resultt, $output1);
					//preg_match('/address:(.*?)phone/si',$got_resultt, $output2);
					$ip_country = !empty($output1[5]) ?  $output1[5].'('.$output1[4].')' :  '';
				}
				$insert = $wpdb->query($wpdb->prepare("INSERT INTO $table_name (username, time,ip,country, success) VALUES (%s, %s, %s, %s, %s)", $submitted_username, current_time('mysql'),$user_ip, $ip_country, 1)); 

				//CHECK IP (BLOCK or Send notification)
				if (strpos($allwd_ips,$user_ip) === false)	{
					if (get_option('optin_for_white_ipss') == 2){
						$admin_mail	= get_option('admin_email');
						$subjectt	="UNKNOWN IP($user_ip) has logged into ".home_url()." ";
						$full_messag="\r\n\r\n Someone with an IP $user_ip (COUNTRY:$ip_country) has logged into your site. \r\n\r\n (if you know him, you can add him to whitelist: " . admin_url('options-general.php?page='.$this->plugin_pageslug) ;
						// To send HTML mail, the Content-type header must be set
						$headers  = "MIME-Version: 1.0\r\nContent-type: text/html\r\nFrom: LOGIN RESTRICT <noreply@noreply.com>\r\nReply-To: noreply@noreply.com\r\nX-Mailer: PHP/".phpversion();

						if ($_SERVER['HTTP_HOST'] != 'localhost'){
							$result = mail( $admin_mail ,$subjectt, $full_messag ,$headersss) ? "okkk" : "problemm";
							//file_put_contents(dirname(__file__).'/aaaa.txt',$result);
						}
					}
				}
			}
		}
	}


	public function logintrackss_funcct()	{ add_submenu_page('options-general.php','LOGIN Restricts','LOGIN Restricts', 'manage_options' ,$this->plugin_pageslug, array($this, 'lgs_page_callback') );}public function lgs_page_callback(){ 
		global $wpdb;	$table_name = $wpdb->prefix . "restrictor_logins";
		//if records cleared
		if (!empty($_POST['logintracks_clear'])) {
			$this->validate_pageload($_POST['update_nonce'],'lo_clear');
			$wpdb->get_results("DELETE FROM ".$table_name." WHERE success='0' OR success='1'");
		}
		if (!empty($_POST['Whois_Method'])) { update_option('lgs_enable_WHOIS',$_POST['Whois_Method']);	}

		$results = $wpdb->get_results("SELECT username,time,UNIX_TIMESTAMP(time) as timestamp,IP,country,success FROM ".$table_name." ORDER BY time DESC");
		?>
		<style>.my_login_tracks tr.succeed{ background-color:#A6FBA6;}.my_login_tracks tr.failed{ background-color:#FFC8BF;}</style>
		<div class="my_login_tracks"><!-- ENABLE/DISABLE OPTIONS -->
			<?php //IF whitelist updated
			if (!empty($_POST['whitelist_ips'])) 			{
				$this->validate_pageload($_POST['update_ips'],'lo_upd');

				update_option('optin_for_white_ipss',$_POST['whitelist_ips']);
				//change IP file
					$final	= $_POST['lgs_white_IPS'];
					$final	= str_replace("\r\n\r\n",	"",		$final);
					$final	= str_replace("\r\n",		"|||",	$final);
				file_put_contents($this->allowed_ipss_file(), $this->StartSYMBOL .$final );
					update_option("backup_ips_".$this->plugin_pageslug.'___'. $this->site_nm() ,  $this->StartSYMBOL .$final);
				
				foreach (get_editable_roles() as $key=>$name){	update_option('lrl__Disallow_'.$key, $_POST['ds_Allow_'.$key]);	}
										
			}
			$allowed_ips 	= str_replace($this->StartSYMBOL, '', file_get_contents($this->allowed_ipss_file()) );
			$whiteip_answer	= get_option('optin_for_white_ipss');
			$d3 = $whiteip_answer == 3 ? "checked" : '';
			$d2 = $whiteip_answer == 2 ? "checked" : '';
			$d1 = $whiteip_answer == 1 || empty($whiteip_answer) ? "checked" : '';
			?>	
			<form method="post" action="">
				<p class="submit">
						<!--
						<b style="font-size:1.2em;">Turn on City Detection too?</b>  <a href="javascript:alert('If this is disabled, then you will see only COUNTRY NAME of visitor, and you have to click that, and you will see full report for that IP. However, you can ENABLE this option, and then you will see CITY name too (along with COUNTRY NAME), but that process prolongs the log-in process by 3 seconds. ');">read more!!</a> 
						<?php if (get_option('lgs_enable_WHOIS')=='yes') {$enab='checked';$disab='';} else{$enab='';$disab='checked';} ?>
						<br/><input type="radio" name="Whois_Method" value="yes" <?php echo $enab;?>  />ENABLE	<input type="radio" name="Whois_Method" value="no"  <?php echo $disab;?> />DISABLE
						<br/><br/>
						-->
					<div class="white_list_ipps" style="background-color: #1EE41E;padding: 5px; margin:0 0 0 10%;width: 60%;">
						<div style="font-size:1.2em;font-weight:bold;">
							IP WHITELISTING setting: (<a href="javascript:alert('1) OFF - do nothing (no restriction to unknown IPS and no notifications).\r\n2) get MAIL NOTIFICATION (if your server supports mailsending) at <?php echo get_option('admin_email');?> (address is changeable from Settings>General) when anyone logins, whose IP is not in this list. \r\n3) Block anyone to access LOGIN page at all [whose IP is not in the list]. \r\r\n(DONT FORGET TO INSERT YOUR IP TOO! HOWEVER,IF YOU BLOCK YOURSELF,enter your wordpress directory (from FTP) and add your IP into this file: WP-CONTENT-\u0022ALLOWED_IP\u0022 . otherwise delete this plugin.)\r\n');">read more!!</a>):
						</div>
						<table style="border: 1px solid;"><tbody><thead><tr><td style="width:140px;">&nbsp;</td><td>&nbsp;</td></tr>
							<tr><td>OFF </td><td><input onclick="lg_radiod();" type="radio" name="whitelist_ips" value="1" <?php echo $d1;?> /></td></tr>
							<tr><td>Mail notification</td><td><input onclick="lg_radiod();" type="radio" name="whitelist_ips" value="2" <?php echo $d2;?> /></td></tr>
							<tr><td>Deny NON-listed IPs</td><td><input onclick="lg_radiod();" type="radio" name="whitelist_ips" value="3" <?php echo $d3;?> /></td></tr>
							<tr><td>&nbsp;</td><td>
							
									<div id="editor_allw_wind" style="display:none;">
									Avoid Restriction for following accounts: (<a href="javascript:alert('This is a good choice, in case you want to create  author/contributor/subscriber users, and you wont have a fear from them, because they are not able modify system options or important settings in dashboard. (if you dont know the details of USER ROLES, then you can view their capabilities in the another opened window)\r\n\r\np.s. Also, you can install \u0022Activity Monitor Plugins\u0022 found in the bottom of this page, so you will see any activities(post creation,modifications or etc) took place in your site dashboard by other users'); window.open('https://codex.wordpress.org/Roles_and_Capabilities#Summary_of_Roles', '_blank');void(0);">Read HELP!</a>)
									<br/>
										<?php foreach (get_editable_roles() as $key=>$name){
											echo $key.'<input type="hidden" name="ds_Allow_'.$key.'" value="yes" /><input type="checkbox" name="ds_Allow_'.$key.'" value="no" '. ('no' == get_option('lrl__Disallow_'.$key) ?  'checked="checked"': '' ) .'/><span style="margin:0 0 0 10px;"></span> ';
										}?>
									</div>
							
							
							
							</td></tr>
						</tbody></table>
									
									
						<div style="float:right;">(your IP is <b style="color:red; background-color:yellow;"><?php echo $_SERVER['REMOTE_ADDR'];?></b>)</div>
						<br/>
						
						<div id="DIV_whiteipieldd" style="overflow-y:auto;">
							<?php	$liness=explode("|||",$allowed_ips);	?>
							<textarea id="whiteips_fieldd" style="width:100%;height:300px;" name="lgs_white_IPS"><?php foreach ($liness as $line) {echo $line."\r\n";}?></textarea>
							<div style="float:right;">
								1)<a href="javascript:alert('You can insert Asterisk IP instead of last 3 chars. For example:\r\n 111.111.111.*\r\n\r\n\r\np.s.In case you dont like this plugin, you may need something \u0022login attempt blocker\u0022 plugins (For example, \u0022Wordfence Security\u0022,\u0022Brute force login protection\u0022,\u0022Login Protection\u0022 or etc...)');">Adding Variable IP</a>
							</div>
						</div>
						
						<script type="text/javascript">
						function lg_radiod()	{
							var valllue = document.querySelector('input[name="whitelist_ips"]:checked').value;
							var DIVipfieldd = document.getElementById("DIV_whiteipieldd");
							var AllowCheckboxes = document.getElementById("editor_allw_wind");
							if(valllue == "2" || valllue == "3")	{DIVipfieldd.style.opacity = "1";}	else {DIVipfieldd.style.opacity = "0.3";}
							if(valllue == "3")	{AllowCheckboxes.style.display="inline-block";}	else {AllowCheckboxes.style.display = "none";}
						}
						lg_radiod();
						</script>
						
						<div style="clear:both;"></div>
						<input type="submit"  value="SAVE" onclick="return foo23();" />
						<input type="hidden" name="update_ips" value="<?php echo wp_create_nonce('lo_upd');?>" />
						<br/>
					</div>
					<script type="text/javascript">
					function foo23()			{
						var IPLIST_VALUE=document.getElementById("whiteips_fieldd").value;
						var user_ip="<?php echo $_SERVER['REMOTE_ADDR'];?>";
						
						var TurnedONOFF = document.querySelector('input[name="whitelist_ips"]:checked').value;
						if (TurnedONOFF != "1")	{
							if (IPLIST_VALUE.indexOf(user_ip) == -1)	{
								if(!confirm("YOUR IP(" + user_ip +") is not in list! Are you sure you want to continue?")){return false;}
							}
						}
						return true;
					}
					</script>
				</p> 
			</form>
			<br/><br/><h2>All logins:</h2>
			<table class="widefat" cellpadding="3" cellspacing="3"><tr><th>Username</th><th>Time(server)</th><th>IP</th><th>COUNTRY (<a href="javascript:alert('This is just an approximate country name. To view the full info for a particular IP, then in this column, click that COUNTRY NAME and you will be redirected to the WHOIS WEBSITE, where you will see the FULL INFORMATION of that IP.');">Read THIS!!</a>)</th><th>Succeed</th></tr>
			<?php	if ($results){	foreach ($results as $e) {
						if(!empty($e->country))	 {$countryyy =  '<a href="'. $this->whois_site . $e->IP.'" target="_blank"> '.$e->country.'</a>';}
						else 					 {$countryyy =  '<a href="'. $this->whois_site . $e->IP.'" target="_blank"> problem_54_from_plugin</a>';}
					echo '<tr class="succeed"><td>'.$e->username.'</td><td>'.$e->time.'</td><td>'.$e->IP.'</td><td>'.$countryyy.'</td><td>succeed<td></tr>';
				}} ?>
			</table>
			
			<!-- clean records -->
			<form method="post" action="">	<input type="hidden" name="logintracks_clear" value="true"/><input type="submit" name="logintracks_submit" value="Clean login data"/><input type="hidden" name="update_nonce" value="<?php echo wp_create_nonce('lo_clear');?>" />
			</form>	
			<br/><br/>p.s. To view other MUST-HAVE Wordpress Plugins, visit <a href="http://codesphpjs.blogspot.com/2014/10/must-have-wordpress-plugins.html#activity_plugins" target="_blank">http://codesphpjs.blogspot.com/2014/10/must-have-wordpress-plugins.html#activity_plugins</a><br/><br/><br/>
		</div>
<?php	}}	?>