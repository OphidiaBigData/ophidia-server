<?php

/*
    Ophidia Server
    Copyright (C) 2012-2021 CMCC Foundation

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

	function get_password() {
		include('env.php');
		$handle = fopen($oph_auth_location . '/users.dat', 'r');
		if ($handle) {
			while (($buffer = fgets($handle, 4096)))
				if (!strcmp($oph_notifier, strtok($buffer, ":\n"))) {
					fclose($handle);
					return strtok(":\n");
			}
			fclose($handle);
		}
		return NULL;
	}

	function send_message($message) {
		if (!($password = get_password()))
			return NULL;
		include('env.php');
		$soap_message = '<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
xmlns:ns0 = "urn:oph"
xmlns:ns1 = "http://schemas.xmlsoap.org/soap/envelope/"
xmlns:xsi = "http://www.w3.org/2001/XMLSchema-instance"
xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header/>
<ns1:Body>
<ns0:oph-notify>
<oph-notify-data>'.$message.'</oph-notify-data>
<oph-notify-json></oph-notify-json>
</ns0:oph-notify>
</ns1:Body>
</SOAP-ENV:Envelope>';
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $oph_ws_protocol.'://'.$oph_ws_host);
		curl_setopt($ch, CURLOPT_PORT, $oph_ws_port);
		curl_setopt($ch, CURLOPT_USERPWD, $oph_notifier .':'. $password);
		curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $soap_message);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: text/xml')); 
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		$xml = curl_exec($ch);
		curl_close($ch);
		return $xml;
	}

	include('env.php');
	if (empty($oph_openid_endpoint))
		header('Location: '.$oph_web_server_secure);
	if (empty($_SERVER['HTTPS']))
		header('Location: '.$oph_web_server_secure.'/openid.php');
	else {
		session_start();
		$error = '';
		$message = 'Login';
		if (isset($_GET['error'])) {
			$error = $_GET['error_description'];
			session_destroy();
		}
		if (isset($_GET['code']) || isset($_POST['code'])) {
			if (isset($_GET['code'])) $code = $_GET['code'];
			else if (isset($_POST['code'])) $code = $_POST['code'];
		}
		if (isset($code) || isset($_SESSION['token']))
			$message = 'Get token';
		if (isset($code)) {
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $oph_openid_endpoint.'/token');
			curl_setopt($ch, CURLOPT_USERPWD, $oph_openid_client_id.':'.$oph_openid_client_secret);
			curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, 'grant_type=authorization_code&code='.$code.'&redirect_uri='.$oph_web_server_secure.'/openid.php');
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www-form-urlencoded')); 
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			$json = curl_exec($ch);
			curl_close($ch);
			$output = json_decode($json, 1);
			if (isset($output['error'])) {
				$error = $output['error_description'];
				$message = 'Login';
			} else {
				$_SESSION['token'] = $output['access_token'];
				$_SESSION['token_type'] = "openid";
				$_SESSION['expires_on'] = date('U') + $output['expires_in'];
				include('userinfo.php');
				if (isset($output['refresh_token'])) {
					$_SESSION['refresh_token'] = $output['refresh_token'];
					send_message('access_token='. $_SESSION['token'] . ';userinfo='. $_SESSION['userinfo'] .';refresh_token='. $_SESSION['refresh_token'] .';');
				} else
					send_message('access_token='. $_SESSION['token'] . ';userinfo='. $_SESSION['userinfo'] .';');
			}
			if (isset($output['error']))
				session_destroy();
		} else if (isset($_GET['submit']) || isset($_POST['submit'])) {
			if (isset($_SESSION['refresh_token'])) {
				$ch = curl_init();
				curl_setopt($ch, CURLOPT_URL, $oph_openid_endpoint.'/token');
				curl_setopt($ch, CURLOPT_USERPWD, $oph_openid_client_id.':'.$oph_openid_client_secret);
				curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
				curl_setopt($ch, CURLOPT_POST, 1);
				curl_setopt($ch, CURLOPT_POSTFIELDS, 'grant_type=refresh_token&refresh_token='.$_SESSION['refresh_token']);
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				$json = curl_exec($ch);
				curl_close($ch);
				$output = json_decode($json, 1);
				if (isset($output['error'])) {
					$error = $output['error_description'];
					$message = 'Login';
				} else {
					$_SESSION['token'] = $output['access_token'];
					$_SESSION['token_type'] = "openid";
					$_SESSION['expires_on'] = date('U') + $output['expires_in'];
					$_SESSION['refresh_token'] = $output['refresh_token'];
					send_message('access_token='. $_SESSION['token'] . ';userinfo='. $_SESSION['userinfo'] .';refresh_token='. $_SESSION['refresh_token'] .';');
				}
				if (isset($output['error']))
					session_destroy();
			} else {
				$continue = true;
				$nonce = hexdec(bin2hex(openssl_random_pseudo_bytes(4)));
				header('Location: '.$oph_openid_endpoint.'/authorize?response_type=code&client_id='.$oph_openid_client_id.'&scope='.$oph_openid_mode.'&redirect_uri='.$oph_web_server_secure.'/openid.php&nonce='.$nonce);
			}
		}
	}
	if (!isset($continue)) {
?>
<!--
    Ophidia Server
    Copyright (C) 2012-2021 CMCC Foundation

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->
<!DOCTYPE HTML>
<HTML>
	<HEAD>
		<TITLE>Ophidia Server</TITLE>
		<LINK href="style.css" rel="stylesheet" type="text/css" />
		<SCRIPT type="text/javascript">
			function show_wait() {
				var error_label = document.getElementById("error");
				error_label.style.color = "green";
				error_label.textContent = "Wait for the request to be processed";
            }
		</SCRIPT>
	</HEAD>
	<BODY>
<?php
		include('userinfo.php');
		if(isset($_SESSION['userid']) && !empty($_SESSION['userid'])) {
?>
		<DIV id="profile">
			<B id="welcome">Welcome : <I><?php
		if (isset($_SESSION['username']) && !empty($_SESSION['username']))
			echo $_SESSION['username'];
		else
			echo $_SESSION['userid'];
?></I></B>
			<B class="activelink"><A href="index.php?logout=yes">Log Out</A></B>
			<B class="activelink"><A href="sessions.php">Session List</A></B>
			<B class="inactivelink">Download</B>
			<B class="inactivelink">Get token</B>
		</DIV>
		<HR/>
<?php
		}
?>
		<DIV id="main">
			<DIV id="login">
				<H2>OpenId Connect</H2>
				<FORM action="openid.php" method="post" onsubmit="show_wait()">
					<INPUT name="submit" type="submit" value="<?php echo $message; ?>"/>
					<SPAN id="error"><?php echo $error; ?></SPAN>
				</FORM>
			</DIV>
		</DIV>
<?php
		if (isset($_SESSION['token']) && !empty($_SESSION['token']) && ($_SESSION['token_type'] == 'openid')) {
?>
		<DIV id="token">
			<H5>Access token <?php
			$residual_time = $_SESSION['expires_on'] - date('U');
			if ($residual_time > 0)
				echo '(valid for ' . $residual_time . ' seconds)';
			else
				echo '(expired)';
			?></H5>
			<TEXTAREA rows="5" cols="133" onclick="this.focus();this.select();" readonly="readonly"><?php echo $_SESSION['token']; ?></TEXTAREA>
		</DIV>
<?php
		}
?>
	</BODY>
</HTML>
<?php
	}
?>
