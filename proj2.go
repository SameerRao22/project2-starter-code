package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"fmt"

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
	Files          map[string]FileStorage
	HMAC_Key       []byte
	UUID           uuid.UUID
	Personal_Key   []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileMetaData struct {
	Appends int
	Owner   []byte
}

type FileStorage struct {
	Meta_Data_Location uuid.UUID
	Encrypt_Key        []byte
	HMAC_Key           []byte
}

type File struct {
	Content []byte
}

type ShareInvitation struct {
	Signature     []byte
	Access_Key    []byte
	File_Location uuid.UUID
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
	userdata.Files = make(map[string]FileStorage)

	marshal, _ := json.Marshal(userdata)
	padded_marshal := Pad(marshal, 16)
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

	ciphertext := secure_text[:(len(secure_text) - 16)]
	hmac_tag := secure_text[(len(secure_text) - 16):]
	computed_tag, _ := userlib.HMACEval(hmac_key, ciphertext)
	if !(userlib.HMACEqual(hmac_tag, computed_tag)) {
		return nil, errors.New("integrity compromised")
	}

	unpadded_ciphertext := Unpad(ciphertext)
	plaintext := userlib.SymDec(key, unpadded_ciphertext)
	plaintext = Unpad(plaintext)
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
	meta_storage_location := uuid.New()
	encryption_key := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(userlib.AESBlockSizeBytes))
	hmac_key := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(16))

	owner_key, _ := userlib.KeystoreGet(userdata.Username)
	encrypted_owner, _ := userlib.PKEEnc(owner_key, []byte(userdata.Username))

	changes := 0
	meta_data := FileMetaData{changes, encrypted_owner}

	marshaled_meta_data, _ := json.Marshal(meta_data)

	meta_string := meta_storage_location.String()
	new_file_name := meta_string + string(rune(changes))
	file_storage_location, _ := uuid.FromBytes([]byte(new_file_name))
	new_file := File{data}

	marshaled_new_file, _ := json.Marshal(new_file)

	padded_meta := Pad(marshaled_meta_data, 16)
	padded_file := Pad(marshaled_new_file, 16)

	encrypted_meta := userlib.SymEnc(encryption_key, userlib.RandomBytes(16), padded_meta)
	encrypted_file := userlib.SymEnc(encryption_key, userlib.RandomBytes(16), padded_file)

	meta_hmac_tag, _ := userlib.HMACEval(hmac_key, encrypted_meta)
	file_hmac_tag, _ := userlib.HMACEval(hmac_key, encrypted_file)
	fmt.Print("Meta HMAC: ")
	fmt.Println(meta_hmac_tag)
	fmt.Print("HMAC Length: ")
	fmt.Println(len(meta_hmac_tag))

	mac_meta := append(encrypted_meta, meta_hmac_tag...)
	mac_file := append(encrypted_file, file_hmac_tag...)

	userlib.DatastoreSet(meta_storage_location, mac_meta)
	userlib.DatastoreSet(file_storage_location, mac_file)

	userdata.Files[filename] = FileStorage{meta_storage_location, encryption_key, hmac_key}

	marshaled_user, _ := json.Marshal(userdata)
	padded_user := Pad(marshaled_user, 16)
	userdata_encrypted := userlib.SymEnc(userdata.Personal_Key, userlib.RandomBytes(16), padded_user)
	user_hmac_tag, _ := userlib.HMACEval(userdata.HMAC_Key, userdata_encrypted)

	user_ciphertext := append(userdata_encrypted, user_hmac_tag...)
	userlib.DatastoreSet(userdata.UUID, user_ciphertext)
	// storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// jsonData, _ := json.Marshal(data)
	// userlib.DatastoreSet(storageKey, jsonData)
	//End of toy implementation
	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var meta_data FileMetaData

	user_files := userdata.Files[filename]
	meta_ciphertext, _ := userlib.DatastoreGet(user_files.Meta_Data_Location)

	encrypted_meta := meta_ciphertext[:(len(meta_ciphertext) - 16)]
	hmac_meta := meta_ciphertext[(len(meta_ciphertext) - 16):]

	hmac_test, _ := userlib.HMACEval(user_files.HMAC_Key, encrypted_meta)
	if !(userlib.HMACEqual(hmac_meta, hmac_test)) {
		fmt.Println("Append File #1")
		return errors.New("integrity compromised")
	}

	plaintext := userlib.SymDec(user_files.Encrypt_Key, encrypted_meta)
	plaintext = Unpad(plaintext)

	error := json.Unmarshal(plaintext, &meta_data)
	if error != nil {
		return errors.New("error with unmarshal")
	}

	meta_string := user_files.Meta_Data_Location.String()
	new_file_name := meta_string + string(rune(meta_data.Appends+1))
	meta_data.Appends += 1
	file_storage_location, _ := uuid.FromBytes([]byte(new_file_name))

	new_file := File{data}

	marshaled_file, _ := json.Marshal(new_file)
	padded_file := Pad(marshaled_file, 16)
	encrypted_file := userlib.SymEnc(user_files.Encrypt_Key, userlib.RandomBytes(16), padded_file)
	tag_file, _ := userlib.HMACEval(user_files.HMAC_Key, encrypted_file)
	hmac_file := append(encrypted_file, tag_file...)

	userlib.DatastoreSet(file_storage_location, hmac_file)

	marshaled_meta, _ := json.Marshal(meta_data)
	padded_meta := Pad(marshaled_meta, 16)
	encrypted_meta_2 := userlib.SymEnc(user_files.Encrypt_Key, userlib.RandomBytes(16), padded_meta)
	tag_meta, _ := userlib.HMACEval(user_files.HMAC_Key, encrypted_meta_2)
	hmac_meta_2 := append(encrypted_meta_2, tag_meta...)
	userlib.DatastoreSet(user_files.Meta_Data_Location, hmac_meta_2)

	return err
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	var meta_data FileMetaData

	user_files := userdata.Files[filename]
	meta_ciphertext, valid_file := userlib.DatastoreGet(user_files.Meta_Data_Location)
	if !valid_file {
		return nil, errors.New("file not found")
	}

	// encrypted_meta := meta_ciphertext[:(len(meta_ciphertext) - 16)]
	// hmac_meta := meta_ciphertext[(len(meta_ciphertext) - 16):]
	encrypted_meta := meta_ciphertext[:(len(meta_ciphertext) - 64)]
	hmac_meta := meta_ciphertext[(len(meta_ciphertext) - 64):]

	hmac_test, _ := userlib.HMACEval(user_files.HMAC_Key, encrypted_meta)

	if !(userlib.HMACEqual(hmac_meta, hmac_test)) {
		fmt.Println("Load File #1")
		fmt.Print("HMAC 1: ")
		fmt.Println(hmac_meta)
		fmt.Print("HMAC 2: ")
		fmt.Println(hmac_test)
		fmt.Println()
		return nil, errors.New("integrity compromised")
	}

	plaintext := userlib.SymDec(user_files.Encrypt_Key, encrypted_meta)
	plaintext = Unpad(plaintext)

	error := json.Unmarshal(plaintext, &meta_data)
	if error != nil {
		return nil, errors.New("error with unmarshal")
	}

	for i := 0; i <= meta_data.Appends; i++ {
		var file File
		meta_string := user_files.Meta_Data_Location.String()
		location, _ := uuid.FromBytes([]byte(meta_string + string(rune(i))))

		secure_file, _ := userlib.DatastoreGet(location)
		encrypted_file := secure_file[:(len(secure_file) - 64)]
		file_hmac := secure_file[(len(secure_file) - 64):]

		file_hmac_test, _ := userlib.HMACEval(user_files.HMAC_Key, encrypted_file)
		if !(userlib.HMACEqual(file_hmac, file_hmac_test)) {
			fmt.Println("Load File Part 2")
			return nil, errors.New("integrity compromised")
		}

		file_plaintext := userlib.SymDec(user_files.Encrypt_Key, encrypted_file)
		file_plaintext = Unpad(file_plaintext)

		unmarshal_error := json.Unmarshal(file_plaintext, &file)
		if unmarshal_error != nil {
			return nil, errors.New("error with unmarshal")
		}
		dataBytes = append(dataBytes, file.Content...)
	}
	return dataBytes, err
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {
	public_key, valid := userlib.KeystoreGet(recipient)

	if !valid {
		return uuid.Nil, errors.New("invalid recipient")
	}

	user_files := userdata.Files[filename]
	access_token := append(user_files.Encrypt_Key, user_files.HMAC_Key...)
	cipher_text, _ := userlib.PKEEnc(public_key, access_token)
	signature, _ := userlib.DSSign(userdata.RSA_Secret_Key, cipher_text)
	invitation := ShareInvitation{signature, cipher_text, user_files.Meta_Data_Location}

	marhsal_invitation, _ := json.Marshal(invitation)
	accessToken = uuid.New()
	userlib.DatastoreSet(accessToken, marhsal_invitation)

	return accessToken, err
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	var invitation ShareInvitation
	public_key, valid := userlib.KeystoreGet(sender)

	if !valid {
		return errors.New("invalid user")
	}

	marshal_invitation, exists := userlib.DatastoreGet(accessToken)
	if !exists {
		return errors.New("file not found")
	}
	error := json.Unmarshal(marshal_invitation, &invitation)
	if error != nil {
		return errors.New("error with unmarshal")
	}

	error = userlib.DSVerify(public_key, invitation.Access_Key, invitation.Signature)
	access_token, error := userlib.PKEDec(userdata.RSA_Secret_Key, invitation.Access_Key)
	key := access_token[:(len(accessToken) - 16)]
	hmac := accessToken[(len(accessToken) - 16):]

	userdata.Files[filename] = FileStorage{invitation.File_Location, key, hmac}
	marshaled_user, _ := json.Marshal(userdata)
	marshaled_user = Pad(marshaled_user, 16)
	encrypted_user := userlib.SymEnc(userdata.Personal_Key, userlib.RandomBytes(16), marshaled_user)
	user_hmac, _ := userlib.HMACEval(userdata.HMAC_Key, encrypted_user)
	ciphertext := append(encrypted_user, user_hmac...)
	userlib.DatastoreSet(userdata.UUID, ciphertext)
	return error
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	var meta_data FileMetaData
	user_files := userdata.Files[filename]
	file_key := user_files.Encrypt_Key
	file_hmac_key := user_files.HMAC_Key

	secure_meta, exists := userlib.DatastoreGet(user_files.Meta_Data_Location)

	if !exists {
		return errors.New("file not found")
	}

	encrypted_meta := secure_meta[:(len(secure_meta) - 64)]
	hmac_meta := secure_meta[(len(secure_meta) - 64):]
	hmac_test, _ := userlib.HMACEval(file_hmac_key, encrypted_meta)
	if !userlib.HMACEqual(hmac_meta, hmac_test) {
		fmt.Println("Revoke File Part 1")
		return errors.New("integrity compromised")
	}
	marshaled_meta := userlib.SymDec(file_key, encrypted_meta)
	marshaled_meta = Unpad(marshaled_meta)

	error := json.Unmarshal(marshaled_meta, &meta_data)
	if error != nil {
		return errors.New("error with unmarshal")
	}

	owner, _ := userlib.PKEDec(userdata.RSA_Secret_Key, meta_data.Owner)
	if string(owner) != userdata.Username {
		return errors.New("user is not the owner")
	}

	new_encryption_key := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(userlib.AESBlockSizeBytes))
	new_hmac_key := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(16))

	marshaled_meta_2, _ := json.Marshal(meta_data)
	marshaled_meta_2 = Pad(marshaled_meta_2, 16)
	encrypted_meta_2 := userlib.SymEnc(new_encryption_key, userlib.RandomBytes(16), marshaled_meta_2)
	new_hmac_tag, _ := userlib.HMACEval(new_hmac_key, marshaled_meta_2)
	encrypted_meta_2 = append(encrypted_meta_2, new_hmac_tag...)
	userlib.DatastoreSet(user_files.Meta_Data_Location, encrypted_meta_2)

	appends := meta_data.Appends
	for i := 0; i <= appends; i++ {
		meta_string := user_files.Meta_Data_Location.String()
		location, _ := uuid.FromBytes([]byte(meta_string + string(rune(i))))
		encrypted_file, _ := userlib.DatastoreGet(location)
		ciphertext := encrypted_file[:(len(encrypted_file) - 64)]
		hmac := encrypted_file[(len(encrypted_file) - 64):]
		hmac_test, _ := userlib.HMACEval(file_hmac_key, encrypted_file)

		if !(userlib.HMACEqual(hmac, hmac_test)) {
			fmt.Println("Revoke File Part 2")
			return errors.New("integrity compromised")
		}

		plaintext := userlib.SymDec(file_key, ciphertext)

		new_ciphertext := userlib.SymEnc(new_encryption_key, userlib.RandomBytes(16), plaintext)
		new_file_hmac_tag, _ := userlib.HMACEval(new_hmac_key, new_ciphertext)
		new_ciphertext = append(new_ciphertext, new_file_hmac_tag...)
		userlib.DatastoreSet(location, new_ciphertext)
	}
	userdata.Files[filename] = FileStorage{user_files.Meta_Data_Location, new_encryption_key, new_hmac_key}

	updated_userdata, _ := json.Marshal(userdata)
	updated_userdata = userlib.SymEnc(userdata.Personal_Key, userlib.RandomBytes(16), updated_userdata)
	userdata_hmac, _ := userlib.HMACEval(userdata.HMAC_Key, updated_userdata)
	updated_userdata = append(updated_userdata, userdata_hmac...)
	userlib.DatastoreSet(userdata.UUID, updated_userdata)
	return err
}
