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

	function make_links_blank($text) {
		return preg_replace(
		     array(
			'/(?(?=<a[^>]*>.+<\/a>)
			     (?:<a[^>]*>.+<\/a>)
			     |
			     ([^="\']?)((?:https?|ftp|bf2|):\/\/[^<> \n\r]+)
			 )/iex',
			'/<a([^>]*)target="?[^"\']+"?/i',
			'/<a([^>]+)>/i',
			'/(^|\s)(www.[^<> \n\r]+)/iex',
			'/(([_A-Za-z0-9-]+)(\\.[_A-Za-z0-9-]+)*@([A-Za-z0-9-]+)
			(\\.[A-Za-z0-9-]+)*)/iex'       ),
		     array(
		       "stripslashes((strlen('\\2')>0?'\\1<a href=\"\\2\">\\2</a>\\3':'\\0'))",
		       '<a\\1',
		       '<a\\1 target="_blank">',
		       "stripslashes((strlen('\\2')>0?'\\1<a href=\"http://\\2\">\\2</a>\\3':'\\0'))",
		       "stripslashes((strlen('\\2')>0?'<a href=\"mailto:\\0\">\\0</a>':'\\0'))"
		       ),
		       $text
		);
	}
	include('env.php');
	include('userinfo.php');
	if (!isset($_SESSION['userid'])) {
		$_SESSION['url'] = $_SERVER['PATH_INFO'].'?'.$_SERVER['QUERY_STRING'];
		if (!empty($_SERVER['HTTPS']) && !isset($_GET['logout']) && isset($_POST['submit']) && !empty($_POST['username']) && !empty($_POST['password'])) {
			$continue = true;
			include('index.php');
		} else
			header('Location: '.$oph_web_server_secure.'/index.php');
	}
	if (isset($_SESSION['userid'])) {
		if (isset($_SESSION['url'])) {
			$target = $_SESSION['url'];
			unset($_SESSION['url']);
		} else
			$target = $_SERVER['PATH_INFO'];

		$session_code = strtok($target,"/");
		if (isset($session_code) && !empty($session_code) && $session_code) {
			$handle = fopen($oph_auth_location . '/users/' . $_SESSION['userid'] . '/sessions/' . $session_code . '.session', 'r');
			if (!$handle) {
				header('HTTP/1.0 403 Forbidden');
?>
<!DOCTYPE HTML>
<HTML>
	<HEAD>
		<TITLE>403 Forbidden</TITLE>
	</HEAD>
	<BODY>
		<H1>Forbidden</H1>
		<P>You don't have permission to access the resource.</P>
	</BODY>
</HTML>
<?php
				exit;
			}
			fclose($handle);
		} else {
			header('Location: '.$oph_web_server_secure.'/index.php');
			exit;
		}

		$file = $oph_web_server_location.'/sessions'.$target;
		if (file_exists($file)) {
			$ext = substr(strrchr($file,'.'),1);
			$filename = substr(strrchr($file,'/'),1);
			$url_to_dir = $oph_web_server.'/sessions'.$target;
			if ($url_to_dir{strlen($url_to_dir)-1} == '/')
				$url_to_dir = substr($url_to_dir,0,strlen($url_to_dir)-1);
			$url_to_dir_p = substr($url_to_dir,0,strrpos($url_to_dir,'/'));
			if (is_dir($file)) {
				include('header.php');
?>
		<P>Content of directory <A href="<?php echo $url_to_dir; ?>"><?php echo $url_to_dir; ?></A></P>
		<HR/>
<?php
				if (substr(strrchr($url_to_dir,'/'),1) != $session_code)
					print '<B><A href="'.$url_to_dir_p.'">Parent directory</A></B>';
				if ($dh = opendir($file)) {
					$dirFiles = array();
					while (($filen = readdir($dh)) !== false) {
						if ( ($filen != ".") && ($filen != "..") ) $dirFiles[] = $filen;
					}
					closedir($dh);
					print '<UL>';
					sort($dirFiles);
					foreach($dirFiles as $filen) print '<LI><A href="'.$url_to_dir.'/'.$filen.'">'.$filen.'</A></LI>';
					print '</UL>';
				} else
					print '<P>The directory is empty.</P>';
				include('tailer.php');
			} else if ( ( isset($filename) && !empty($filename) && (!isset($ext) || empty($ext)) ) || ($ext == 'htm') || ($ext == 'html') ) {
				header('Content-Type: text/html');
				include('header.php');
				if ($filename == 'experiment') {
?>
		<P>Command list for <A href="<?php echo $oph_web_server; ?>/sessions/<?php echo $session_code; ?>/experiment"><?php echo $oph_web_server; ?>/sessions/<?php echo $session_code; ?>/experiment</A></P>
<?php
				} else {
?>
		<P>File <?php echo $filename; ?></P>
<?php
				}
?>
		<HR/>
		<B><A href="<?php echo $url_to_dir_p; ?>">Parent directory</A></B>
<?php
				readfile($file);
				include('tailer.php');
			} else if ($ext == 'json') {
				if (isset($_GET['download'])) {
					header('Content-Description: File Transfer');
					header('Content-Type: application/json');
					header('Content-Disposition: attachment; filename="'.basename($file).'"');
					header('Content-Transfer-Encoding: binary');
					header('Expires: 0');
					header('Pragma: no-cache');
					header('Content-Length: '.filesize($file));
					readfile($file);
				} else {
					$download = 1;
					header('Content-Type: text/html');
					include('header.php');
?>
		<P>JSON file <A href="<?php echo $url_to_dir; ?>"><?php echo $url_to_dir; ?></A></P>
		<HR/>
		<B><A href="<?php echo $url_to_dir_p; ?>">Parent directory</A></B><P/>
<?php
					if ($file_handle = fopen($file,"r")) {
						while (!feof($file_handle)) {
							$tok = strtok(str_replace(" ","&nbsp;",fgets($file_handle)), "\"");
							while ($tok) {
								print make_links_blank($tok);
								$tok = strtok("\"");
								if ($tok)
									print "\"";
							}
							print "<BR/>";
						}
						fclose($file_handle);
					}
					include('tailer.php');
				}
			} else if ($ext == 'nc') {
				header('Content-Description: File Transfer');
				header('Content-Type: application/x-netcdf');
				header('Content-Disposition: attachment; filename="'.basename($file).'"');
				header('Content-Transfer-Encoding: binary');
				header('Expires: 0');
				header('Pragma: no-cache');
				header('Content-Length: '.filesize($file));
				readfile($file);
			} else if ($ext == 'csv') {
				header('Content-Description: File Transfer');
				header('Content-Type: text/csv');
				header('Content-Disposition: attachment; filename="'.basename($file).'"');
				header('Expires: 0');
				header('Pragma: no-cache');
				header('Content-Length: '.filesize($file));
				readfile($file);
			} else if ($ext == 'png') {
				header('Content-Type: image/png');
				readfile($file);
			} else
				header('Location: '.$oph_web_server.'/sessions/'.$session_code.'/experiment');
		} else {
			header('HTTP/1.0 404 Not Found');
?>
<!DOCTYPE HTML>
<HTML>
	<HEAD>
		<TITLE>404 Not Found</TITLE>
	</HEAD>
	<BODY>
		<H1>Not Found</H1>
		<P>The resource has not been found on this server.</P>
	</BODY>
</HTML>
<?php
		}
	}
?>
