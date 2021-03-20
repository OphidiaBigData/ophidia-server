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
	if (empty($oph_aaa_endpoint))
		header('Location: '.$oph_web_server_secure);
	if (empty($_SERVER['HTTPS']))
		header('Location: '.$oph_web_server_secure.'/aaa.php');
	else {
		session_start();
		$error = '';
		if (isset($_GET['error'])) {
			$error = $_GET['error_description'];
			session_destroy();
		}
		if (isset($_GET['token']) || isset($_POST['token'])) {
			if (isset($_GET['token'])) $_SESSION['token'] = $_GET['token'];
			else if (isset($_POST['token'])) $_SESSION['token'] = $_POST['token'];
			$_SESSION['token_type'] = "aaa";
		}
		if (isset($_GET['username']) || isset($_POST['username'])) {
			if (isset($_GET['username'])) $_SESSION['userid'] = $_GET['username'];
			else if (isset($_POST['username'])) $_SESSION['userid'] = $_POST['username'];
		}
		if (!isset($_SESSION['username'])) {
			$fname = "";
			if (isset($_GET['fname']) || isset($_POST['fname'])) {
				if (isset($_GET['fname'])) $fname = $_GET['fname'];
				else if (isset($_POST['fname'])) $fname = $_POST['fname'];
			}
			$lname = "";
			if (isset($_GET['lname']) || isset($_POST['lname'])) {
				if (isset($_GET['lname'])) $lname = $_GET['lname'];
				else if (isset($_POST['lname'])) $lname = $_POST['lname'];
			}
			if (!empty($fname) && !empty($lname))
				$_SESSION['username'] = $fname . ' ' . $lname;
			else
				$_SESSION['username'] = $_SESSION['userid'];
		}
	}
	if (1) {
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
				<H2>AAA</H2>
				<FORM action="aaa.php">
					<SPAN id="error"><?php echo $error; ?></SPAN>
				</FORM>
			</DIV>
		</DIV>
<?php
		if (isset($_SESSION['token']) && !empty($_SESSION['token']) && ($_SESSION['token_type'] == 'aaa')) {
?>
		<DIV id="token">
			<H5>Access token</H5>
			<TEXTAREA rows="1" cols="133" onclick="this.focus();this.select();" readonly="readonly"><?php echo $_SESSION['token']; ?></TEXTAREA>
		</DIV>
<?php
		}
?>
	</BODY>
</HTML>
<?php
	}
?>
