Leo Registration Server
----------------------
#### Dependencies
To run this server, you must have a relatively recent build of Go installed.

#### Cloning This Repo
Golang expects projects to be in a certain path layout
```
$HOME/go/src/github.com/leo-backend
```
where $HOME is whatever you want. You should also set:

```
export GOPATH=$HOME/golang
export PATH=$PATH:$GOPATH/bin
```

#### Configuration Setup
Under normal operation, the server relies on 4 external files, all in PKCS8 
format:
- A public key for encypting get_user requests
- A private key for encypting get_user requests
- A certificate for using TLS
- A private key associated with the certificate

To configure the server, edit `config/config.go` to contain the correct paths 
for all 4 files. You may run the server without TLS, also by editing the config 
file, and therefore omit the cert and second private key. You can generate a
public and private key pair in PKCS8 format with the following commands:
```
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private.pem -out public.pem
```
#### Running the Server
To run the project locally:
```
cd $HOME/golang/src/github.com/leo-backend
go get ./
go install
go run server.go
```

To run the project in production:
```
cd $HOME/golang/src/github.com/leo-backend
go get ./
go install
$HOME/golang/bin/leo-backend
```