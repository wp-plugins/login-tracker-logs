<?php
/*
Plugin Name: Login Tracker Logs
Plugin URI:
Description: Logs successful logins  (To deny access to WP-LOGIN only to selected IP's, then see - http://codesphpjs.blogspot.com/2014/09/allow-wp-login-only-to-specific-ips.html )
Version: 1.1
Author: selnomeria
Author URI: http://codesphpjs.blogspot.com
*/
//include_once(dirname(__file__).'/trunk/login-tracker-logs.php');

$newlgs= new Login_Tracker_logs;
class Login_Tracker_logs 
{
	protected $whois_site= 'http://www.whois.com/whois/';
	
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



	public function lgs_login_checker() 
	{
		global $wpdb;	$table_name = $wpdb->prefix."tracked_logins";
		$submitted_username=sanitize_text_field(esc_attr($_POST['log']));
		
		if (!empty($submitted_username) && !empty($_POST['pwd']) && !empty($_POST['testcookie']))
		{
			$creds = array();
			$creds['user_login']	= $submitted_username;
			$creds['user_password']	= $_POST['pwd'];
			$creds['remember']		= true;
			$user = wp_signon( $creds, false );
			if ( !is_wp_error($user) )
			{
				$user_ip	= $_SERVER['REMOTE_ADDR'];
					if (get_option('lgs_enable_ip_country')=='yes') 
					{
						$got_resultt = $this->get_remote_data($this->whois_site.$user_ip);
						preg_match('/address:(.*?)address:(.*?)address:(.*?)address:(.*?)address:(.*?)phone/si',$got_resultt, $output);
						$ip_country = !empty($output[5]) ?  $output[5].'('.$output[4].')' :  '';
					}
					else
					{
						$ip_country = 'click-here';
					}
				$insert = $wpdb->query($wpdb->prepare("INSERT INTO $table_name (username, time,ip,country, success) VALUES (%s, %s, %s, %s, %s)", $submitted_username, current_time('mysql'),$user_ip, $ip_country, 1)); 
			}
		}
	}



	public function logintrackss_funcct(){	add_submenu_page('options-general.php','LOGIN Tracks','LOGIN Tracks', 'manage_options' ,'my-lgs-submenu-page', array($this, 'lgs_page_callback') );}
	//output of page
	public function lgs_page_callback()
	{
		global $wpdb;	$table_name = $wpdb->prefix . "tracked_logins";
		if ($_POST['logintracks_clear']=='true') {
			$wpdb->get_results("DELETE FROM ".$table_name." WHERE success='0' OR success='1'");
		}
		if (!empty($_POST['country_detct'])) {update_option('lgs_enable_ip_country',$_POST['country_detct']);}
		$results = $wpdb->get_results("SELECT username,time,UNIX_TIMESTAMP(time) as timestamp,IP,country,success FROM ".$table_name." ORDER BY time DESC");
		?>
		<style>
		.my_login_tracks tr.succeed{ background-color:#A6FBA6;}
		.my_login_tracks tr.failed{ background-color:#FFC8BF;}
		</style>
		
		<div class="my_login_tracks">
			<h2>All logins:</h2>
			<table class="widefat" cellpadding="3" cellspacing="3"><tr><th>Username</th><th>Time</th><th>IP</th><th>COUNTRY</th><th>Succeed</th></tr>
			<?php
			if ($results){foreach ($results as $e) {
						if(!empty($e->country))
							 {$countryyy =  '<a href="'. $this->whois_site . $e->IP.'" target="_blank">'.$e->country.'</a>';}
						else {$countryyy =  '<a href="'. $this->whois_site . $e->IP.'" target="_blank">problem_plugin_55_ip</a>';}
		
					echo '<tr class="succeed"><td>'.$e->username.'</td><td>'.$e->time.'</td><td>'.$e->IP.'</td><td>'.$countryyy.'</td><td>succeed<td></tr>';
				}
			}
			?>
			</table>
			<form method="post" action="">
					<input type="hidden" name="logintracks_clear" value="true"/>
					<input type="submit" name="logintracks_submit" value="Clean login data"/>
			</form>
			<br/><br/>			
			
			<form method="post" action="">
				<p class="submit">
					<b style="font-size:1.2em;">Turn on automatic COUNTRY DETECTION while user log-ins?</b>  [If disabled, then you will have to click "click-here" button under the "COUNTRY" column to see user's IP info. The fair is because, that automatic COUNTRY logging just prolongs the successful login process by 2 seconds, but maybe thats no problem, because he only log-ins once in a day or so :) ]
					<?php if (get_option('lgs_enable_ip_country')=='yes') {$enab='checked';$disab='';} else{$enab='';$disab='checked';} ?>
					<br/>
					<input type="radio" name="country_detct" value="yes" <?php echo $enab;?>  />ENABLE
					<input type="radio" name="country_detct" value="no"  <?php echo $disab;?> /> DISABLE
					<br/><input type="submit"  value="SAVE"/>
				</p> 
			</form>
			<br/><br/>

			<div class="">
			-This plugin is good with login attempt blockers, like "Brute force login protection" or "Login Protection" 
			<br/>-(To deny access to WP-LOGIN only to selected IP's, then see - http://codesphpjs.blogspot.com/2014/09/allow-wp-login-only-to-specific-ips.html )
		
			</div>
		</div>
		<?php
	}
}	
?>