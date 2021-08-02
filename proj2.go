package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func Pad(plaintext []byte, padsize int) (padded_message []byte) {
	num_padding := padsize - (len(plaintext) % padsize)
	var padding []byte
	for i := 0; i < num_padding; i++ {
		// padding[i] = byte(num_padding)
		padding = append(padding, byte(num_padding))
	}
	padded_message = append(plaintext, padding...)
	return
}

func Unpad(ciphertext []byte) (message []byte) {
	num_padding := int(ciphertext[len(ciphertext)-1])
	padding_index := len(ciphertext) - num_padding
	message = ciphertext[:padding_index]
	return
}

// User is the structure definition for a user record.
type User struct {
	Username       string
	RSA_Secret_Key userlib.PKEDecKey
	Files          map[string]uuid.UUID
	HMAC_Key       []byte
	UUID           uuid.UUID
	Personal_Key   []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileMetaData struct {
	Appends     int
	Owner       []byte
	Encrypt_Key []byte
	HMAC_Key    []byte
}

type File struct {
	content []byte
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	var rsa_public userlib.PKEEncKey
	var rsa_secret userlib.PKEDecKey
	rsa_public, rsa_secret, _ = userlib.PKEKeyGen()

	userlib.KeystoreSet(username, rsa_public)

	userdata.Username = username
	userdata.RSA_Secret_Key = rsa_secret
	//userdata.Storage_Key = userlib.Argon2Key([]byte(password), []byte(username), uint32(len(username)))
	padded_username := Pad([]byte(username), 16)
	userdata.UUID = bytesToUUID([]byte(padded_username))

	userdata.Personal_Key = userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESBlockSizeBytes))
	userdata.HMAC_Key = userlib.Argon2Key([]byte(password), []byte(username), uint32(16))
	userdata.Files = make(map[string]uuid.UUID)

	marshal, _ := json.Marshal(userdata)
	padded_marshal := Pad(marshal, userlib.AESBlockSizeBytes)
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	encrypted_marshal := userlib.SymEnc(userdata.Personal_Key, iv, padded_marshal)

	hmac_tag, _ := userlib.HMACEval(userdata.HMAC_Key, encrypted_marshal)
	secure_message := append(encrypted_marshal, hmac_tag...)

	userlib.DatastoreSet(userdata.UUID, secure_message)
	userdataptr = &userdata
	return &userdata, err
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	_, user_found := userlib.KeystoreGet(username)

	if !user_found {
		return nil, errors.New("invalid user")
	}
	padded_username := Pad([]byte(username), 16)
	UUID := bytesToUUID([]byte(padded_username))
	key := userlib.Argon2Key([]byte(password), []byte(username), uint32(len(username)))
	hmac_key := userlib.Argon2Key([]byte(password), []byte(username), uint32(16))
	secure_text, login := userlib.DatastoreGet(UUID)

	if !login {
		return nil, errors.New("wrong password")
	}

	ciphertext := secure_text[:(len(secure_text) - userlib.HashSizeBytes)]
	hmac_tag := secure_text[(len(secure_text) - userlib.HashSizeBytes):]
	computed_tag, _ := userlib.HMACEval(hmac_key, ciphertext)
	if !(userlib.HMACEqual(hmac_tag, computed_tag)) {
		return nil, errors.New("integrity compromised")
	}

	unpadded_ciphertext := Unpad(ciphertext)
	plaintext := userlib.SymDec(key, unpadded_ciphertext)
	error := json.Unmarshal(plaintext, &userdata)
	if error != nil {
		return nil, errors.New("error with unmarshal")
	}
	return userdataptr, err
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	jsonData, _ := json.Marshal(data)
	userlib.DatastoreSet(storageKey, jsonData)
	//End of toy implementation

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	return dataBytes, nil
	//End of toy implementation

	return
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
