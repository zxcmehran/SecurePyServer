# Python HTTP Server w/ User Authentication and HTTPS support

## What's different?
You might be familiar with [SimpleHTTPServer](https://docs.python.org/2/library/simplehttpserver.html) module already. It will give you a simple and easy to use solution for hosting content by just typing `python -m SimpleHTTPServer` in a terminal.

Here is a revised version of SimpleHTTPServer with HTTPS and User Authentication support. 

## Installing
You just need a clone:

    $ git clone https://github.com/zxcmehran/SecurePyServer

## Usage

    $ ./SecureHTTPServer.py [webroot] [host:port] [username:password] [certfile] [keyfile]
`webroot` is the path to web root, relative to current working directory. Specify a dot "." to use current directory.

There is no need to specify both host and port in `host:port`. You might want to enter port or host only. Default value is 8000.

Specify a Username and Password as `username:password` for **HTTP Basic Authentication**. Using ":" will disable authentication. Disabled by default.

You can activate **HTTPS** using a Certificate and Key pair. Use `certfile` and `keyfile` to set file paths.

Certificate file should contain PEM encoded version of certificates chain as described in [Python SSL Documentation](https://docs.python.org/2/library/ssl.html#certificate-chains).

Key file argument can be omitted if the key is included in certificate file.

## License
[MIT](https://tldrlegal.com/license/mit-license) License
