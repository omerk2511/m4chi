# m4chi
m4chi is a toy VPN implementation for Linux using TUN/TAP

## Usage

```
usage: client.py [-h] iface ip port

m4gnum's vpn client

positional arguments:
  iface       iface identifier
  ip          vpn server's ip
  port        vpn server's port

optional arguments:
  -h, --help  show this help message and exit
```

```
usage: server.py [-h] [--base BASE] ip port

m4gnum's vpn server

positional arguments:
  ip           vpn server's ip
  port         vpn server's port

optional arguments:
  -h, --help   show this help message and exit
  --base BASE  vpn ip range base
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)

## Screenshots

### LAN HTTP Serving over VPN
![http serving](https://github.com/omerk2511/m4chi/blob/master/assets/1.png?raw=true)

## Authors
- **Omer Katz** - [omerk2511](https://github.com/omerk2511)
