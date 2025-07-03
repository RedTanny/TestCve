# hello_c

This project is a simple C program that:
- Takes an input string (key)
- Generates a SHA256 hash using OpenSSL
- Sends the hash to a server using libcurl via an HTTP POST request (REST API style: `save=key`)

## Requirements
- OpenSSL development libraries
- libcurl development libraries
- GCC or compatible C compiler

On Fedora/RedHat:
```
sudo dnf install openssl-devel libcurl-devel gcc
```

On Ubuntu/Debian:
```
sudo apt-get install libssl-dev libcurl4-openssl-dev build-essential
```

## Build
```
make
```

## Usage
```
./main <key> <server_url>
```

- `<key>`: The input string to hash
- `<server_url>`: The URL of the server to send the hash to (e.g., `http://localhost:8080/save`)

Example:
```
./main mysecretkey http://localhost:8080/save
```

This will print the SHA256 hash and send it to the server as a POST request with the body `save=<hash>`. 