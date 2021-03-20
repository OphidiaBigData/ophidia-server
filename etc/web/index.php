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

	include('env.php');
	if (empty($_SERVER['HTTPS']))
		header('Location: '.$oph_web_server_secure.'/index.php');
	else {
		$error='';
		if (isset($_GET['logout'])) {
			session_start();
			if (isset($_SESSION['token']) && !empty($_SESSION['token']) && ($_SESSION['token_type'] == 'aaa')) {
				$ch = curl_init();
				curl_setopt($ch, CURLOPT_URL, $oph_aaa_endpoint.'/engine/api/checkout_data');
				curl_setopt($ch, CURLOPT_POST, 1);
				curl_setopt($ch, CURLOPT_POSTFIELDS, 'token='.$_SESSION['token']);
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				$userinfo_json = curl_exec($ch);
				curl_close($ch);
			}
			if (session_destroy()) header('Location: '.$oph_web_server_secure.'/index.php');
		} else if (isset($_POST['submit'])) {
			$error = 'Username or Password are not valid';
			if (!empty($_POST['username']) && !empty($_POST['password'])) {
				$username = $_POST['username'];
				$password = $_POST['password'];

				// User security check
				$result = false;
				$handle = fopen($oph_auth_location.'/users.dat', 'r');
				if ($handle) {
					$sha_password = '*' . strtoupper(sha1(sha1($password, true)));
					while (($buffer = fgets($handle, 4096))) {
						$user = strtok($buffer,":\n");
						$passwd = strtok(":\n");
						if (!strcmp($username,$user) && ( !strcmp($password,$passwd) || !strcmp($sha_password,$passwd) )) {
							$result = true;
							break;
						}
					}
					fclose($handle);
				}
				if ($result) {
					session_start();
					$_SESSION['userid'] = $username;
					if (isset($_SESSION['url'])) {
						header('Location: '.$oph_web_server.'/sessions.php'.$_SESSION['url']);
						unset($_SESSION['url']);
					} else
						header('Location: '.$oph_web_server_secure.'/index.php');
				}
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
<?php
		include('userinfo.php');
		$isset_userid = isset($_SESSION['userid']) && !empty($_SESSION['userid']);
		$isset_token = isset($_SESSION['token']) && !empty($_SESSION['token']);
		if (!$isset_userid && !$isset_token) {
			if (!empty($oph_openid_endpoint)) {
?>
		<SCRIPT type="text/javascript">
			function login_with_openid() {
				var error_label = document.getElementById("error");
				error_label.style.color = "green";
				error_label.textContent = "Wait for the request to be processed";
				location.href = '<?php echo $oph_web_server_secure; ?>/openid.php?submit=Login';
            }
		</SCRIPT>
<?php
			}
			if (!empty($oph_aaa_endpoint)) {
?>
		<SCRIPT type="text/javascript">
			window.addEventListener("message", receiveMessage, false);
			function receiveMessage(event)
			{
				if (event.origin !== "<?php echo $oph_aaa_endpoint; ?>")
					return;
				var error_label = document.getElementById("error");
				var data = event.data;
				if (!data.success) {
					error_label.style.color = "red";
					if (data.error !== "")						
						error_label.textContent = data.error;
					else
						error_label.textContent = "Authorization error";
					return;
				}
				if (data.error !== "") {
					error_label.style.color = "red";
					error_label.textContent = data.error;
					return;
				}
				var user_info = data.user_info;
				error_label.textContent = "";
				location.href = '<?php echo $oph_web_server_secure; ?>/aaa.php?token=' + user_info.user_token + '&username=' + user_info.user.username + '&fname=' + user_info.user.fname + '&lname=' + user_info.user.lname;
			}
			function openWin(url, w, h) {
				var left = (screen.width / 2) - (w / 2);
				var top = (screen.height / 2) - (h / 2);
				w = window.open(url, '_blank');
				w.focus();
			}
			function login_with_aaa() {
				var error_label = document.getElementById("error");
				error_label.style.color = "green";
				error_label.textContent = "Wait for the request to be processed";
				openWin('<?php echo $oph_aaa_endpoint; ?>');
				return false;
            }
		</SCRIPT>
<?php
			}
		}
?>
	</HEAD>
	<BODY>
<?php
		if($isset_userid) {
?>
		<DIV id="profile">
			<B id="welcome">Welcome : <I><?php
		if (isset($_SESSION['username']) && !empty($_SESSION['username']))
			echo $_SESSION['username'];
		else
			echo $_SESSION['userid'];
?></I></B>
			<B class="activelink"><A href="index.php?logout=yes">Log Out</A></B>
			<B class="inactivelink">Session List</B>
			<B class="inactivelink">Download</B>
<?php
			if ($isset_token) {
				if ($_SESSION['token_type'] === 'openid') {
?>
			<B class="activelink"><A href="openid.php">Get token</A></B>
<?php
				} else if ($_SESSION['token_type'] === 'aaa') {
?>
			<B class="activelink"><A href="aaa.php">Get token</A></B>
<?php
				}
			}
?>
		</DIV>
		<HR/>
<?php
			// Load sessions
			print '<H5><TABLE align="center" border="1" width="100%"><TR><TH>Available sessions</TH><TH>Creation time</TH><TH>Active</TH><TH>Label</TH><TH>Number of tasks</TH><TH>Last access time</TH></TR>';
			$dirFiles = scandir($oph_auth_location.'/users/'.$_SESSION['userid'].'/sessions');
			rsort($dirFiles);
			foreach($dirFiles as $filen) {
				if ( ($filen != ".") && ($filen != "..") ) {
					$ext = substr(strrchr($filen,'.'),1);
					if ( $ext == 'session' ) {
						$sessionn = substr($filen,0,strrpos($filen,'.'));
						if ($file_handle = fopen($oph_auth_location.'/users/'.$_SESSION['userid'].'/sessions/'.$filen,"r")) {
							print '<TR>';
							print '<TD><A href="'.$oph_web_server.'/sessions.php/'.$sessionn.'/experiment">'.$oph_web_server.'/sessions/'.$sessionn.'/experiment</A></TD>';
							while (!feof($file_handle)) {
								$conf_row = fgets($file_handle);
								$key = substr($conf_row,0,strrpos($conf_row,'='));
								$value = substr(strrchr($conf_row,'='),1);
								switch ($key) {
									case "OPH_CREATION_TIME":
									case "OPH_LAST_ACCESS_TIME":
										$value = gmdate("Y-m-d H:i:s",$value);
									case "OPH_ACTIVE":
									case "OPH_LABEL":
									case "OPH_LAST_WORKFLOW":
										print '<TD><A href="'.$oph_web_server.'/sessions.php/'.$sessionn.'/experiment">'.$value.'</A></TD>';
										break;
								}
							}
							fclose($file_handle);
							print '</TR>';
						}
					}
				}
			}
			print '</TABLE></H5>';
		} else {
?>
		<DIV id="main"><DIV id="login">
			<H2>Login Form</H2>
			<FORM action="" method="post">
				<LABEL>Username :</LABEL>
				<INPUT id="name" name="username" placeholder="username" type="text" />
				<LABEL>Password :</LABEL>
				<INPUT id="password" name="password" placeholder="**********" type="password" />
				<INPUT name="submit" type="submit" value=" Login " />
<?php
			if (!empty($oph_openid_endpoint)) {
?>
				<INPUT name="openid" type="button" value=" Login with OpenId " onclick="login_with_openid()"/>
<?php
			}
?>
<?php
			if (!empty($oph_aaa_endpoint)) {
?>
				<INPUT name="aaa" type="button" value=" Login with AAA " onclick="login_with_aaa()"/>
<?php
			}
?>
				<SPAN id="error"><?php echo $error; ?></SPAN>
			</FORM>
		</DIV></DIV>
<?php
		}
?>
	</BODY>
</HTML>
<?php
	}
?>
