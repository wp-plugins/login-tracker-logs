<?php
if (!class_exists('GeoIP')){include_once( dirname(__file__)."/geoip.inc" );}
$gi = geoip_open(dirname(__file__)."/GeoIP.dat", GEOIP_STANDARD); 
$country_name = geoip_country_name_by_addr($gi, $user_ip );
geoip_close($gi);
//if ($country_name == 'Germany') { echo "You are from Germanyy";}
?>