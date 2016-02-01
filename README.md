<h1>Ophidia Server</h1>

<h3>Description</h3>
The Ophidia Server is the Ophidia front-end. It supports several interfaces (WS-I, GSI/VOMS, WPS) and works as a web service.</br>
The server also includes user authorization and confidentialy (based on TLS/SSL protocol for WS-I and WPS).</br>
The server processes JSON Requests structured according to the Ophidia Workflow JSON Schema and returns JSON Responses back to clients.

<h3>Requirements</h3>
In order to compile and run the Ophidia Server, make sure you have the following packages (all available through CentOS official repositories and the epel repository) properly installed:
<ol>
  <li>jansson and jansson-devel</li>
  <li>libxml2 and libxml2-devel</li>
  <li>libcurl and libcurl-devel</li>
  <li>openssl and openssl-devel</li>
  <li>libssh2 and libssh2-devel</li>
  <li>mysql-community-server</li>
  <li>gsoap</li>
  <li>globus-common-devel (only for GSI support)</li>
  <li>globus-gsi-credential-devel (only for GSI support)</li>
  <li>globus-gsi-proxy-core-devel (only for GSI support)</li>
  <li>globus-gssapi-gsi-devel (only for GSI support)</li>
  <li>voms-devel (only for GSI support)</li>
</ol>
<b>Note</b>:</br>
This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit.

<h3>How to Install</h3>
The server needs digital certificates enabling TLS/SSL protected communication. <\br>
The code has been packaged with GNU Autotools, so look at the INSTALL file or simply type</br></br>
<code>
./configure --prefix=<i>prefix</i></br>
make</br>
make install</br>
cp authz/* <i>prefix</i>/</br>
</br></code>
Type:</br>
<code>./configure --help</code></br>
to see all available options.
Finally, copy authz/* into the installation path and configure your users. To do this, you can use the tool <i>oph\_manage\_user</i>.</br>
If you want to use the program system-wide, remember to add its installation directory to your PATH.</br>

<h3>How to Launch</h3>
<code>oph_server</code></br></br>
Type:</br>
<code>oph_server -h</code></br>
to see all other available options.

<h3>User Management</h3>
To add a new user type:</br></br>
<code>oph_manage_user -a <i>add</i> -u <i>username</i> -p <i>password</i></code></br></br>
Type:</br></br>
<code>oph_manage_user -h</code></br></br>
to see all other available options.</br></br>

Further information can be found at <a href="http://ophidia.cmcc.it/documentation">http://ophidia.cmcc.it/documentation</a>.

