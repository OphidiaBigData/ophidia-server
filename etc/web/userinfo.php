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

	session_start();
	if (isset($_SESSION['token']) && !empty($_SESSION['token']) && (!isset($_SESSION['userid']) || empty($_SESSION['userid']))) {
		if (!empty($oph_openid_endpoint) && ($_SESSION['token_type'] === 'openid')) {
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $oph_openid_endpoint.'/userinfo');
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Authorization: Bearer '.$_SESSION['token'])); 
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			$userinfo_json = curl_exec($ch);
			curl_close($ch);
			$userinfo = json_decode($userinfo_json, 1);
			if (strlen($userinfo['error']) > 0)
				session_destroy();
			else {
				$_SESSION['userid'] = $userinfo['sub'];
				$_SESSION['username'] = $userinfo['name'];
				$_SESSION['userinfo'] = $userinfo_json;
			}
		} else if (!empty($oph_aaa_endpoint) && ($_SESSION['token_type'] === 'aaa')) {
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $oph_aaa_endpoint.'/engine/api/verify_token');
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, 'token='.$_SESSION['token']);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			$userinfo_json = curl_exec($ch);
			curl_close($ch);
			$userinfo = json_decode($userinfo_json, 1);
			if ($userinfo['response'] !== 'invalid token')
				$_SESSION['userid'] = $userinfo['response'];
			else
				session_destroy();
		}
	}
?>
