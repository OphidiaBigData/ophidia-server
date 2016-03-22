<?php

/*
    Ophidia Server
    Copyright (C) 2012-2016 CMCC Foundation

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
	if (empty($_SERVER['HTTPS'])) header('Location: '.$oph_web_server_secure.'/index.php');
	else 
	{
		$error='';
		if (isset($_GET['logout']))
		{
			session_start();
			if (session_destroy()) header('Location: '.$oph_web_server_secure.'/index.php');
		}
		else if (isset($_POST['submit']))
		{
			$error = 'Username or Password is invalid';
			if (!empty($_POST['username']) && !empty($_POST['password'])) 
			{
				$username=$_POST['username'];
				$password=$_POST['password'];

				// User security check
				$result = false;
				$handle = fopen($oph_auth_location . '/authz/users.dat', 'r');
				if ($handle)
				{
					$sha_password = '*' . strtoupper(sha1(sha1($password, true)));
					while (($buffer = fgets($handle, 4096)))
					{
						$user = strtok($buffer,":\n");
						$passwd = strtok(":\n");
						if (!strcmp($username,$user) && ( !strcmp($password,$passwd) || !strcmp($sha_password,$passwd) ))
						{
							$result = true;
							break;
						}
					}
					fclose($handle);
				}
				if ($result)
				{
					session_start();
					$_SESSION['userid']=$username;
					if (isset($_SESSION['url']))
					{
						header('Location: '.$oph_web_server.'/sessions.php'.$_SESSION['url']);
						unset($_SESSION['url']);
					}
					else header('Location: '.$oph_web_server_secure.'/index.php');
				}
			}
		}
	}
	if (!isset($continue))
	{
?>
<!--
    Ophidia Server
    Copyright (C) 2012-2016 CMCC Foundation

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
		session_start();
		if(isset($_SESSION['userid']) && !empty($_SESSION['userid'])) {
?>
		<DIV id="profile">
			<B id="welcome">Welcome : <I><?php echo $_SESSION['userid']; ?></I></B>
			<B class="activelink"><A href="index.php?logout=yes">Log Out</A></B>
			<B class="inactivelink">Session List</B>
			<B class="inactivelink">Download</B>
		</DIV>
		<HR/>
<?php
			// Load sessions
			print '<H5><TABLE align="center" border="1" width="100%"><TR><TH>Available sessions</TH><TH>Creation time</TH><TH>Active</TH><TH>Label</TH><TH>Number of tasks</TH><TH>Last access time</TH></TR>';
			$dirFiles = scandir($oph_auth_location.'/authz/users/'.$_SESSION['userid'].'/sessions');
			rsort($dirFiles);
			foreach($dirFiles as $filen)
			{
				if ( ($filen != ".") && ($filen != "..") )
				{
					$ext = substr(strrchr($filen,'.'),1);
					if ( $ext == 'session' )
					{
						$sessionn = substr($filen,0,strrpos($filen,'.'));
						if ($file_handle = fopen($oph_auth_location.'/authz/users/'.$_SESSION['userid'].'/sessions/'.$filen,"r"))
						{
							print '<TR>';
							print '<TD><A href="'.$oph_web_server.'/sessions.php/'.$sessionn.'/experiment">'.$oph_web_server.'/sessions/'.$sessionn.'/experiment</A></TD>';
							while (!feof($file_handle))
							{
								$conf_row = fgets($file_handle);
								$key = substr($conf_row,0,strrpos($conf_row,'='));
								$value = substr(strrchr($conf_row,'='),1);
								switch ($key)
								{
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
