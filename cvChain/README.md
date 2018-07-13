# cvChain

## go version

`go version go1.10.3 darwin/amd64`

## build

```
go get -u --tags nopkcs11 github.com/hyperledger/fabric/core/chaincode/shim
go build --tags nopkcs11
```
## verndor

```
govendor init
govendor add +external  // Add all external package, or
govendor add github.com/external/pkg // Add specific external package
```