# CS-Umbrella / Webshell Plugin Server

It's a web ssh proxy. If deployed on certain server it can transform it to web ssh client. It is for remote ssh connections, not for the connection to the same server where it's deployed. See [Shellinabox](https://code.google.com/archive/p/shellinabox/) if you want to have just web ssh server on the same server you want connect to.

It is distributed in the form of Docker container which includes Shellinabox and python wrapper script and enables remote connections to arbitrary servers. It's based on the original [Shellinabox](https://code.google.com/archive/p/shellinabox/) and the [idea](https://blog.bartlweb.net/2013/10/ssh-web-gateway-mit-dem-opensource-tool-shellinabox/) of ssh client invocation.

The project includes next features (both IPv4 and IPv6 are OK):
1. serverip/port/login of the host to connect in the URL
2. serverip/port/login from the terminal (interactive in a browser)
3. specify idle interval and terminate such clients (to protect from hung and broken terminals)
4. specify the list of networks (in CIDR format) which are permitted to connect
5. specify default serverip/port/login
6. supports secret private keys storage in HashiCorp's [Vault](https://www.vaultproject.io)

The code doesn't support DNS names for servers because It involves ambiguity in name-to-ip resolution and it's not my case, basically. The container is as basic as can be and doesn't include extra authentication and limitations. For an open environment usage it is recommended to place nginx as a reverse proxy ahead of it and implement additional authentication and other restrictions (I believe that per-ip connection limit is the basic one).

# Usage

The most basic usage involves to run docker container and specify allowed networks in CIDR format (use comma to separate them). By default gray networks are specified - 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7)

```bash
docker run -d --privileged --security-opt seccomp=unconfined --name webshell -p 8018:80 -e ALLOWED_NETWORKS=0.0.0.0/0 bwsw/webshell
```

Navigate to http://hostname.com:8018/ to specify server ip, port and login interactively or 
- http://hostname.com:8018/?serverip
- http://hostname.com:8018/?serverip/port
- http://hostname.com:8018/?serverip/port/login
- http://hostname.com:8018/?serverip/port/login/vault-token/vault/secret/key

to use URL-based and default values

## Parameters

1. **SSH_PORT** - default port to use (if not specified - 22)
2. **USERNAME** - default login to use (if not specified - root)
3. **DEFAULT_IP** - default ip to use (if not specified, both ipv4 and ipv6 are ok)
4. **ALLOWED_NETWORKS** - comma-separated list of CIDRs (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7, both ipv4 and ipv6 are ok)
5. **INACTIVITY_INTERVAL** - amount of seconds of noIO between remote server and browser after which the monitor script must terminate the connection (default 60)
6. **VAULT_ENABLED** - specifies either HashiCorp Vault enabled or not
7. **VAULT_VALUE** - specifies value field name for secret key where to get private ssh key
8. **VAULT_URL** - specifies where Vault is deployed (e.g. http(s)://somewhere.com:8200/v1).

## HashiCorp's Vault integration notes

Private SSH keys which are stored in Vault must be Base64-encoded, e.g.

```bash
base64 ~/.ssh/id_rsa
```

Current implementation requires that for the Vault calling part either guarantees safety to show the token in URI or provides one time (limited) Vault token which doesn't fit for reuse.

Also, keep in mind, that the code **creates** temporary file for SSH identity file and removes it after SSH command invocation, so keep the docker container with bwsw/webshell secure. The feature involves potential security vulnerability, so the code must be audited properly by security engineers.

## Author

Ivan Kudryavtsev @ [Bitworks Software, Ltd.](https://bitworks.software/)

## License

Published under Apache v2.0
