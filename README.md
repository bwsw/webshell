# webshell

It's a web ssh proxy. If deployed on certain server it can transform it to web ssh client. It is for remote ssh connections, not for the connection to the same server where it's deployed (see shellinabox https://code.google.com/archive/p/shellinabox/) if you want to have just web ssh server to the server.

Docker container which includes Shellinabox and python wrapper script which enables remote connections to arbitrary servers. It's based on original Shellinabox (https://code.google.com/archive/p/shellinabox/) and wrapper idea of ssh client invocation found somewhere in the Internet.

The project includes next abilities (both IPv4 and IPv6 are OK):
1. to specify serverip/port/login of the host to connect in the URL
2. to specify serverip/port/login from the terminal (interactive in a browser)
3. specify idle interval and terminate such clients (to protect from hung and broken terminals)
4. specify the list of networks (in CIDR format) which are permitted to connect
5. specify default serverip/port/login

The code doesn't support DNS names for servers because It involves ambiguity in name-to-ip resolution and it's not my case, basically. The container is as basic as can be and doesn't include extra authentication and limitations. For an open environment usage it is recommended to place nginx as a reverse proxy ahead of it and implement additional authentication and other restrictions (I believe that per-ip connection limit is the basic one).

# Usage

```bash
docker run -d --name webshell -p 8018:80 -e ALLOWED_NETWORKS=0.0.0.0/0 bwsw/webshell
```
