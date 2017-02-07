To run this file, you should have a dir format that looks something like:

```
$HOME/golang/src/github.com/leo-backend
```

where $HOME is whatever. You should also set:

```
export GOPATH=$HOME/golang
export PATH=$PATH:$GOPATH/bin
```

To run:

```
cd $HOME/golang/src/github.com/leo-backend
go get ./
go install
go run server.go
```

The server expects that there be files:
```
$HOME/golang/src/github.com/leo-backend/settings/keys/private.pem
$HOME/golang/src/github.com/leo-backend/settings/keys/public.pem
```
Which must be RSA keys in PKCS8 file format.

Disclaimer: All of the above might be wrong.