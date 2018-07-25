/*
 * Copyright IBM Corp All Rights Reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"strings"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/chaincode/shim/ext/entities"
	"github.com/hyperledger/fabric/protos/peer"
)

const (
	// DECKEY dec key
	DECKEY = "DECKEY"
	// ENCKEY enc key
	ENCKEY = "ENCKEY"
	// IV iv
	IV = "IV"
)

// SimpleAsset implements a simple chaincode to manage an asset
type SimpleAsset struct {
	bccspInst bccsp.BCCSP
}

// Init is called during chaincode instantiation to initialize any
// data. Note that chaincode upgrade also calls this function to reset
// or to migrate data.
func (t *SimpleAsset) Init(stub shim.ChaincodeStubInterface) peer.Response {
	// do nothing
	return shim.Success(nil)
}

// Invoke is called per transaction on the chaincode. Each transaction is
// either a 'get' or a 'set' on the asset created by Init function. The Set
// method may create a new asset by specifying a new key-value pair.
func (t *SimpleAsset) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	// Extract the function and args from the transaction proposal
	fn, args := stub.GetFunctionAndParameters()
	tMap, err := stub.GetTransient()
	if err != nil {
		return shim.Error(fmt.Sprintf("Could not retrieve transient, err %s", err))
	}

	var result string
	switch fn {
	case "addRecord":
		result, err = addRecord(stub, args)
		break
	case "getRecord":
		result, err = getRecord(stub, args)
		break
	case "encRecord":
		// make sure there's a key in transient - the assumption is that
		// it's associated to the string "ENCKEY"
		if _, in := tMap[ENCKEY]; !in {
			return shim.Error(fmt.Sprintf("Expected transient encryption key %s", ENCKEY))
		}
		result, err = t.Encrypter(stub, args[0:], tMap[ENCKEY], tMap[IV])
		break
	case "decRecord":
		// make sure there's a key in transient - the assumption is that
		// it's associated to the string "DECKEY"
		if _, in := tMap[DECKEY]; !in {
			return shim.Error(fmt.Sprintf("Expected transient decryption key %s", DECKEY))
		}
		result, err = t.Decrypter(stub, args[0:], tMap[DECKEY], tMap[IV])
		break
	default:
		return shim.Error(fmt.Sprintf("Unsupported function %s", fn))
	}
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success([]byte(result))
}

// addRecord stores the asset (both key and value) on the ledger. If the key exists,
// it will override the value with the new one
func addRecord(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	if len(args) != 4 {
		return "", fmt.Errorf("Incorrect arguments. Expecting a key and a value")
	}
	key := args[0] + ":" + args[1]
	value := args[2] + ":" + args[3]
	err := stub.PutState(key, []byte(value))
	if err != nil {
		return "", fmt.Errorf("Failed to set asset: %s", args[0])
	}
	return value, nil
}

// getRecord returns the value of the specified asset key
func getRecord(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	if len(args) != 2 {
		return "", fmt.Errorf("Incorrect arguments. Expecting a key")
	}

	key := args[0] + ":" + args[1]
	value, err := stub.GetState(key)
	result := strings.Split(string(value), ":")
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s with error: %s", args[0], err)
	}
	if value == nil {
		return "", fmt.Errorf("Asset not found: %s", args[0])
	}
	return result[0], nil
}

// Encrypter exposes how to write state to the ledger after having
// encrypted it with an AES 256 bit key that has been provided to the chaincode through the
// transient field
func (t *SimpleAsset) Encrypter(stub shim.ChaincodeStubInterface, args []string, encKey, IV []byte) (string, error) {
	// create the encrypter entity - we give it an ID, the bccsp instance, the key and (optionally) the IV
	ent, err := entities.NewAES256EncrypterEntity("ID", t.bccspInst, encKey, IV)
	if err != nil {
		return "", fmt.Errorf("entities.NewAES256EncrypterEntity failed, err %s", err)
	}

	if len(args) != 4 {
		return "", fmt.Errorf("Expected 4 parameters to function Encrypter")
	}

	key := args[0] + ":" + args[1]
	value := args[2] + ":" + args[3]
	cleartextValue := []byte(value)

	// here, we encrypt cleartextValue and assign it to key
	err = encryptAndPutState(stub, ent, key, cleartextValue)
	if err != nil {
		return "", fmt.Errorf("encryptAndPutState failed, err %+v", err)
	}
	return value, nil
}

// Decrypter exposes how to read from the ledger and decrypt using an AES 256
// bit key that has been provided to the chaincode through the transient field.
func (t *SimpleAsset) Decrypter(stub shim.ChaincodeStubInterface, args []string, decKey, IV []byte) (string, error) {
	// create the encrypter entity - we give it an ID, the bccsp instance, the key and (optionally) the IV
	ent, err := entities.NewAES256EncrypterEntity("ID", t.bccspInst, decKey, IV)
	if err != nil {
		return "", fmt.Errorf("entities.NewAES256EncrypterEntity failed, err %s", err)
	}

	if len(args) != 2 {
		return "", fmt.Errorf("Expected 2 parameters to function Decrypter")
	}

	key := args[0] + ":" + args[1]
	// here we decrypt the state associated to key
	cleartextValue, err := getStateAndDecrypt(stub, ent, key)
	if err != nil {
		return "", fmt.Errorf("getStateAndDecrypt failed, err %+v", err)
	}

	result := strings.Split(string(cleartextValue), ":")
	// here we return the decrypted value as a result
	return result[0], nil
}

// main function starts up the chaincode in the container during instantiate
func main() {
	factory.InitFactories(nil)
	err := shim.Start(&SimpleAsset{factory.GetDefault()})
	if err != nil {
		fmt.Printf("Error starting SimpleAsset chaincode: %s", err)
	}
}
