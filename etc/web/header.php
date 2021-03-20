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
<?php
	include('env.php');
?>
<!DOCTYPE HTML>
<HTML>
	<HEAD>
		<TITLE>Ophidia Server</TITLE>
		<LINK href="<?php echo $oph_web_server; ?>/style.css" rel="stylesheet" type="text/css" />
	</HEAD>
	<BODY>
<?php
	include('userinfo.php');
	if (isset($_SESSION['userid']) && !empty($_SESSION['userid'])) {
?>
		<DIV id="profile">
			<B id="welcome">Welcome : <I><?php
		if (isset($_SESSION['username']) && !empty($_SESSION['username']))
			echo $_SESSION['username'];
		else
			echo $_SESSION['userid'];
?></I></B>
			<B class="activelink"><A href="<?php echo $oph_web_server_secure; ?>/index.php?logout=yes">Log Out</A></B>
			<B class="activelink"><A href="<?php echo $oph_web_server_secure; ?>/index.php">Session List</A></B>
<?php
		if (isset($download) && !empty($download))
			print '<B class="activelink"><A href="?download=yes">Download</A></B>';
		else
			print '<B class="inactivelink">Download</B>';
?>
<?php
		if (isset($_SESSION['token']) && !empty($_SESSION['token'])) {
			if ($_SESSION['token_type'] === 'openid') {
?>
			<B class="activelink"><A href="<?php echo $oph_web_server_secure; ?>/openid.php">Get token</A></B>
<?php
			} else if ($_SESSION['token_type'] === 'aaa') {
?>
			<B class="activelink"><A href="<?php echo $oph_web_server_secure; ?>/aaa.php">Get token</A></B>
<?php
			}
		}
?>
		</DIV>
		<HR/>
<?php
	}
?>

