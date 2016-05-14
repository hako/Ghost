// Package ghost provides methods for interacting with the Snapchat API.
package ghost

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	phone "github.com/dicefm/extra-terrestrial/phone"
	"github.com/hako/casper"
)

// Snapchat general constants.
const (
	SnapchatVersion   = "9.19.0.0"
	URL               = "https://app.snapchat.com"
	UserAgent         = "Snapchat/" + SnapchatVersion + " (HTC One; Android 5.0.2#482424.2#21; gzip)"
	AcceptLang        = "en"
	AcceptLocale      = "en_US"
	Pattern           = "0001110111101110001111010101111011010001001110011000110001000110"
	Secret            = "iEk21fuwZApXlz93750dmW22pw389dPwOk"
	StaticToken       = "m198sOkJEn37DjqZ32lpRu76xmw288xSQ9"
	BlobEncryptionKey = "M02cnQ51Ji97vwT4"
	JPEGSignature     = "FFD8FFE0"
	MP4Signature      = "000000186674797033677035"
	ZipSignature      = "504B0304"
)

// Snapchat media constants.
const (
	MediaImage SnapchatMediaType = iota
	MediaVideo
	MediaVideoNoAudio

	MediaFriendRequest
	MediaFriendRequestImage
	MediaFriendRequestVideo
	MediaFriendRequestNoAudio
)

// Snapchat Snap statuses.
const (
	StatusNone SnapchatStatus = iota - 1
	StatusSent
	StatusDelivered
	StatusOpened
	StatusScreenShot
)

// Snapchat Friend statuses.
const (
	FriendConfirmed SnapchatFriendStatus = iota
	FriendUnconfirmed
	FriendBlocked
	FriendDeleted
	FriendFollowing = 6
)

// Snapchat Privacy settings
const (
	PrivacyEveryone SnapchatPrivacySetting = iota
	PrivacyFriends
)

// Supported Snaptag formats.
const (
	SnapTagPNG SnapTagImageFormat = "PNG"
	SnapTagSVG SnapTagImageFormat = "SVG"
)

// SnapchatMediaType represents the a Snapchat media type.
type SnapchatMediaType int

// SnapchatStatus represents a Snapchat status type.
type SnapchatStatus int

// SnapchatFriendStatus represents a Snapchat friend status type.
type SnapchatFriendStatus int

// SnapchatPrivacySetting represents a Snapchat privacy setting.
type SnapchatPrivacySetting int

// SnapTagImageFormat represents a downloadable Snaptag image format.
type SnapTagImageFormat string

// Account represents a single Snapchat account.
type Account struct {
	GoogleMail     string
	GooglePassword string
	CasperClient   *casper.Casper
	Debug          bool
	Token          string
	Username       string
	Password       string
	UserID         string
	ProxyURL       *url.URL
}

// Error handles errors returned by ghost methods.
type Error struct {
	Err SnapchatError
}

func (e Error) Error() string {
	return fmt.Sprintf("Error: Snapchat said: %s, Status code: %d, Logged In: %t", e.Err.Message, e.Err.Status, e.Err.Logged)
}

// NewAccount creates a new Snapchat Account of type *Account.
func NewAccount(apiKey, apiSecret string, debug bool) *Account {
	casperClient := &casper.Casper{
		APIKey:    apiKey,
		APISecret: apiSecret,
		Debug:     debug,
	}
	ghostAcc := &Account{
		CasperClient: casperClient,
		Debug:        debug,
	}
	return ghostAcc
}

// setCredentials attaches the username, password to the casper client.
func (acc *Account) setCredentials(username, password string) {
	acc.CasperClient.Username = username
	acc.CasperClient.Password = password
	acc.Username = username
}

// DecodeSnaptag decodes Snapchat 'Snaptags'.
func DecodeSnaptag(snaptag string) {
	b, _ := hex.DecodeString(snaptag)
	for _, v := range b {
		fmt.Println(strconv.FormatInt(int64(v), 2))
	}
}

// AddPKCS5 pads plaintext with PKCS5.
func AddPKCS5(plaintext []byte) []byte {
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

// RemovePKCS5 removes padding from plaintext.
func RemovePKCS5(plaintext []byte) []byte {
	unpadding := int(plaintext[len(plaintext)-1])
	return plaintext[:(len(plaintext) - unpadding)]
}

// DecryptECB decrypts data using ECB.
func DecryptECB(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	if len(data) < aes.BlockSize {
		fmt.Println("Ciphertext is too short")
	}

	if len(data)%aes.BlockSize != 0 {
		fmt.Println("Ciphertext is not a multiple of the block size")
	}

	j := len(data) / aes.BlockSize
	var decrypted []byte
	for i := 0; i < j; i++ {
		low := i * aes.BlockSize
		high := low + aes.BlockSize
		out := make([]byte, aes.BlockSize)
		block.Decrypt(out, data[low:high])
		tmp := [][]byte{decrypted, out}
		decrypted = bytes.Join(tmp, nil)
	}

	return decrypted
}

// EncryptECB encrypts data using ECB.
func EncryptECB(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	if len(data)%aes.BlockSize != 0 {
		fmt.Println("Plaintext is not a multiple of the block size")
	}

	j := len(data) / aes.BlockSize
	var encrypted []byte
	for i := 0; i < j; i++ {
		low := i * aes.BlockSize
		high := low + aes.BlockSize
		out := make([]byte, aes.BlockSize)
		block.Encrypt(out, data[low:high])
		tmp := [][]byte{encrypted, out}
		encrypted = bytes.Join(tmp, nil)
	}

	return encrypted
}

// DecryptCBC decrypts data using CBC.
func DecryptCBC(data []byte, b64Iv, b64Key string) []byte {

	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		fmt.Println(err)
	}
	iv, err := base64.StdEncoding.DecodeString(b64Iv)
	if err != nil {
		fmt.Println(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	if len(data) < aes.BlockSize {
		fmt.Println("Ciphertext is too short")
	}

	if len(data)%aes.BlockSize != 0 {
		fmt.Println("Ciphertext is not a multiple of the block size")
	}

	decryptor := cipher.NewCBCDecrypter(block, iv)
	decryptor.CryptBlocks(data, data)

	return data
}

// IsJPEG checks if data is a JPEG image.
func IsJPEG(data []byte) bool {
	sig, err := hex.DecodeString(JPEGSignature)
	if err != nil {
		return false
	}
	if bytes.Equal(data[:len(sig)], sig) {
		return true
	}
	return false
}

// IsMP4 checks if data is a MP4 video.
func IsMP4(data []byte) bool {
	sig, err := hex.DecodeString(MP4Signature)
	if err != nil {
		return false
	}
	if bytes.Equal(data[:len(sig)], sig) {
		return true
	}
	return false
}

// IsZIP checks if data is a ZIP file.
func IsZIP(data []byte) bool {
	sig, err := hex.DecodeString(ZipSignature)
	if err != nil {
		return false
	}
	if bytes.Equal(data[:len(sig)], sig) {
		return true
	}
	return false
}

// CalculateAge calculates the age of a Snapchat user.
func CalculateAge(date string) (string, error) {
	now := time.Now()
	birthday, err := time.Parse("2006-01-02", date)
	if err != nil {
		return "", err
	}
	return strconv.Itoa(now.Year() - birthday.Year()), nil
}

// structToJSON is a helper method for converting Snapchat structs To JSON.
func structToJSON(jsn interface{}) string {

	bytes, err := json.Marshal(jsn)
	if err != nil {
		fmt.Println(err)
	}
	return string(bytes)
}

// AddJPEGSignature appends a JPEG magic number to data.
func AddJPEGSignature(data []byte) []byte {
	sig, err := hex.DecodeString(JPEGSignature)
	if err != nil {
		fmt.Println(err)
	}
	return append(sig, data...)
}

// AddMP4Signature appends a MP4 magic number to data.
func AddMP4Signature(data []byte) []byte {
	sig, err := hex.DecodeString(MP4Signature)
	if err != nil {
		fmt.Println(err)
	}
	return append(sig, data...)
}

// Timestamp generates timestamps in miliseconds.
func Timestamp() string {
	return strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)
}

// UUID4 Generates (RFC 4122) compatible UUIDs.
func UUID4() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println(err)
	}
	return fmt.Sprintf("%04x-%02x-%02x-%02x-%06x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// MediaID creates Snapchat Media UUIDs using username.
func MediaID(username string) string {
	return fmt.Sprintf("%s~%s", strings.ToUpper(username), UUID4())
}

// EncryptSnap is a small wrapper around AddPKCS5 & EncryptECB.
func EncryptSnap(file []byte) ([]byte, error) {
	if len(file) == 0 {
		return nil, errors.New("File does not exist.")
	}
	padFile := AddPKCS5(file)
	encryptedFile := EncryptECB([]byte(BlobEncryptionKey), padFile)
	return encryptedFile, nil
}

// DetectMedia is a small wrapper around IsJPEG & IsMP4.
func DetectMedia(file []byte) (string, error) {
	var mt SnapchatMediaType
	if len(file) == 0 {
		return "", errors.New("File does not exist.")
	}
	if IsJPEG(file) == true {
		mt = MediaImage
	} else if IsMP4(file) == true || IsZIP(file) == true {
		mt = MediaVideo
	} else {
		return "", errors.New("Unknown file type.")
	}
	return strconv.Itoa(int(mt)), nil
}

// RequestToken generates request tokens on each Snapchat API request.
func RequestToken(AuthToken, timestamp string) string {
	hash := sha256.New()
	io.WriteString(hash, Secret+AuthToken)
	first := hex.EncodeToString(hash.Sum(nil))
	hash.Reset()
	io.WriteString(hash, timestamp+Secret)
	second := hex.EncodeToString(hash.Sum(nil))
	var bits string
	for i, c := range Pattern {
		if c == '0' {
			bits += string(first[i])
		} else {
			bits += string(second[i])
		}
	}
	return bits
}

// SetAuthToken sets the auth token auth to current Snapchat account acc.
func (acc *Account) SetAuthToken(auth string) {
	acc.Token = auth
}

// SetAuthTokenWithUsername sets the auth token auth to current Snapchat account acc.
// with a username username.
// Usually used for an account which has already logged into Snapchat.
func (acc *Account) SetAuthTokenWithUsername(username, auth string) {
	acc.Token = auth
	acc.CasperClient.AuthToken = auth
	acc.Username = username
	acc.CasperClient.Username = username
}

// SendRequest performs HTTP requests.
func (acc *Account) SendRequest(method, endpoint string, data map[string]string) *http.Response {
	var tr *http.Transport
	var req *http.Request
	var form url.Values

	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if acc.ProxyURL != nil {
		tr.Proxy = http.ProxyURL(acc.ProxyURL)
	}

	if acc.Debug == true {
		fmt.Printf(method+"\t%s\n", URL+endpoint)
	}

	if data != nil {

		form = url.Values{}
		for k, v := range data {
			form.Add(k, v)
			if acc.Debug == true {
				fmt.Printf("%s\t%s\n", k, v)
			}
		}
	}

	client := &http.Client{Transport: tr}

	if method == "GET" {
		req, _ = http.NewRequest(method, URL+endpoint, nil)
	} else {
		req, _ = http.NewRequest(method, URL+endpoint, strings.NewReader(form.Encode()))
	}

	req.Header.Set("User-Agent", UserAgent)

	if method == "POST" {

		if endpoint == "/bq/solve_captcha" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		androidAuthToken := acc.Token

		if endpoint == "/loq/login" || endpoint == "/loq/device_id" || endpoint == "/bq/solve_captcha" {
			clientAuthToken, err := acc.CasperClient.GetClientAuthToken(acc.Username, acc.Password, data["timestamp"])
			if err != nil {
				fmt.Println(err)
			}
			req.Header.Set("X-Snapchat-Client-Auth-Token", "Bearer "+androidAuthToken)
			req.Header.Set("X-Snapchat-Client-Auth", clientAuthToken)
		} else {
			req.Header.Set("X-Snapchat-Client-Auth-Token", "Bearer "+androidAuthToken)
		}
	}

	req.Header.Set("Accept-Language", AcceptLang)
	req.Header.Set("Accept-Locale", AcceptLocale)

	resp, err := client.Do(req)

	if err != nil {
		fmt.Println(err)
	}

	return resp
}

// Performs multipart HTTP requests. (Not fully implemented)
/*func SendMultipartRequest(endpoint string, data map[string]string, path string) *http.Response {
	// For debugging purposes only!
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	ms := multipartstreamer.New()

	err := ms.WriteFields(data)
	if err != nil {
		fmt.Println(err)
	}

	err = ms.WriteFile("data", path)
	if err != nil {
		fmt.Println(err)
	}

	req, err := http.NewRequest("POST", URL+endpoint, ms.GetReader())
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Language", AcceptLang)
	req.Header.Add("Content-Type", ms.ContentType)
	req.ContentLength = ms.Len()
	var b []byte
	ms.GetReader().Read(b)
	fmt.Println(b)
	if err != nil {
		fmt.Println(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	return resp
}*/

// SendMultipartRequest performs multipart HTTP requests.
func (acc *Account) SendMultipartRequest(endpoint string, data map[string]string, path string, opts casper.Options) *http.Response {
	var tr *http.Transport

	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	err := writer.SetBoundary("Boundary+0xAbCdEfGbOuNdArY")
	if err != nil {
		fmt.Println(err)
	}
	mh := make(textproto.MIMEHeader)
	if path != "" {
		mh.Set("Content-Disposition", "form-data; name=\"data\"; filename=\"data\"")
	}
	mh.Set("Content-Type", "application/octet-stream")
	partWriter, err := writer.CreatePart(mh)
	if err != nil {
		fmt.Println(err)
	}
	if err != nil {
		fmt.Println(err)
	}

	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			fmt.Println(err)
		}

		_, err = io.Copy(partWriter, file)
		if err != nil {
			fmt.Println(err)
		}
	}

	for k, v := range data {
		mh = make(textproto.MIMEHeader)
		dpos := fmt.Sprintf("form-data; name=\"%s\"", k)
		mh.Set("Content-Disposition", dpos)
		partWriter, err = writer.CreatePart(mh)
		if nil != err {
			panic(err)
		}
		mh.Set("Boundary", writer.Boundary())
		io.Copy(partWriter, bytes.NewBufferString(v))
	}

	err = writer.Close()
	if err != nil {
		fmt.Println(err)
	}

	if acc.ProxyURL != nil {
		tr.Proxy = http.ProxyURL(acc.ProxyURL)
	}

	if acc.Debug == true {
		fmt.Printf("POST"+"\t%s\n", URL+endpoint)
	}

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("POST", URL+endpoint, body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=Boundary+0xAbCdEfGbOuNdArY")

	req.Header.Set("Accept", opts.Headers["Accept"])
	req.Header.Set("Accept-Locale", "en")
	req.Header.Set("User-Agent", opts.Headers["User-Agent"])
	req.Header.Set("Content-Length", string(body.Len()))
	req.Header.Set("X-Snapchat-Client-Auth-Token", opts.Headers["X-Snapchat-Client-Auth-Token"])
	req.Header.Set("X-Snapchat-UUID", opts.Headers["X-Snapchat-UUID"])

	if acc.Debug == true {
		for k, v := range req.Header {
			fmt.Println(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	return resp
}

// Register registers a new Snapchat account.
func (acc *Account) Register(username, password, email, birthday string) (casper.Register, error) {
	preregistration, err := acc.CasperClient.Register(username, password, email, birthday)
	if err != nil {
		return casper.Register{}, err
	}
	acc.SetAuthTokenWithUsername(username, preregistration.AuthToken)
	return preregistration, nil
}

// RegisterUsername registers a new Snapchat username.
func (acc *Account) RegisterUsername(selectedUsername, email string) (casper.Updates, error) {
	registration, err := acc.CasperClient.RegisterUsername(selectedUsername, email)
	if err != nil {
		return casper.Updates{}, err
	}
	return registration, nil
}

// VerifyPhoneNumber sends a phone number to Snapchat for verification.
func (acc *Account) VerifyPhoneNumber(phoneNumber string) (map[string]interface{}, error) {
	number, err := phone.Normalise(phoneNumber, "")
	if err != nil {
		return nil, err
	}
	body, err := acc.CasperClient.VerifyPhoneNumber(phoneNumber, number.Country[:2])
	if err != nil {
		return nil, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// SendSMSCode sends an SMS code to Snapchat.
func (acc *Account) SendSMSCode(code string) (map[string]interface{}, error) {
	body, err := acc.CasperClient.SendSMSCode(code)
	if err != nil {
		return nil, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// GetCaptcha fetches a captcha puzzle from snapchat.
func (acc *Account) GetCaptcha() (string, error) {
	captcha, err := acc.CasperClient.GetCaptcha()
	if err != nil {
		return "", err
	}
	if acc.Debug == true {
		fmt.Println("< CAPTCHA ZIP: " + captcha.ID + " >")
	}
	captchaID := strings.Replace(captcha.ID, ".zip", "", 1)
	ioutil.WriteFile(captcha.ID, captcha.Data, 0644)
	return captchaID, nil
}

// SolveCaptcha solves the captcha puzzle from snapchat.
// An account is validated afterwards.
func (acc *Account) SolveCaptcha(captchaID, solution string) (string, error) {
	body, err := acc.CasperClient.SolveCaptcha(captchaID, solution)
	if err != nil {
		return "", err
	}
	return body, nil
}

//	RegisterExpire expires a device id.
//  (This happens when the user presses cancel when signing up.)
// func (acc *Account) RegisterExpire(device_id string) map[string]interface{} {
// 	ts := Timestamp()

// 	data := map[string]string{
// 		"timestamp":        ts,
// 		"req_token":        RequestToken(acc.Token, ts),
// 		"device_unique_id": device_unique_id,
// 	}

// 	resp := acc.SendRequest("POST", "/loq/and/register_exp", data)
// 	body, ioErr := ioutil.ReadAll(resp.Body)
// 	fmt.Println(string(body))
// 	if ioErr != nil {
// 		fmt.Println(ioErr)
// 	}

// 	var parsed map[string]interface{}
// 	json.Unmarshal(body, &parsed)
// 	return parsed
// }

// Login logs the user into Snapchat.
func (acc *Account) Login(username, password string) (casper.Updates, error) {
	acc.setCredentials(username, password)
	body, err := acc.CasperClient.Login(username, password)
	if err != nil {
		return casper.Updates{}, err
	}
	acc.Token = body.UpdatesResponse.AuthToken
	acc.UserID = body.UpdatesResponse.UserID
	return body, nil
}

// Logout logs the user out of Snapchat.
func (acc *Account) Logout() (bool, error) {
	body, err := acc.CasperClient.Logout()
	if err != nil {
		return false, err
	}
	if acc.Debug == true {
		fmt.Println("Logged out?: " + strconv.FormatBool(body))
	}
	return true, nil
}

// FetchBlob fetches a single media blob.
func (acc *Account) FetchBlob(username, id string) []byte {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(acc.Token, ts),
		"id":        id,
	}

	resp := acc.SendRequest("POST", "/bq/blob", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}

	return body
}

// FetchStoryBlob fetches and decrypts a story media blob.
func (acc *Account) FetchStoryBlob(mediaID, b64Iv, b64Key string) error {
	resp := acc.SendRequest("GET", "/bq/story_blob?story_id="+mediaID+"&t=0&mt=1&encoding=compressed", nil)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		return ioErr
	}
	if acc.Debug == true {
		fmt.Println("< BLOB: " + mediaID + " >")
	}
	data := DecryptCBC(body, b64Iv, b64Key)
	media, err := DetectMedia(data)
	mediaType, err := strconv.Atoi(media)
	if err != nil {
		return err
	}
	if SnapchatMediaType(mediaType) == MediaVideo {
		ioutil.WriteFile(mediaID+".zip", data, 0644)
	} else {
		ioutil.WriteFile(mediaID+".jpg", data, 0644)
	}
	return nil
}

// IPRouting gets IP Routing URLs.
func (acc *Account) IPRouting() (map[string]interface{}, error) {
	body, err := acc.CasperClient.IPRouting()
	if err != nil {
		return nil, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// Updates gets all the Snapchat updates for the authenticated account.
func (acc *Account) Updates() (casper.Updates, error) {
	body, err := acc.CasperClient.Updates()
	if err != nil {
		return casper.Updates{}, err
	}
	acc.UserID = body.UpdatesResponse.UserID
	return body, nil
}

// SuggestedFriends fetches all the Snapchat suggested friends.
func (acc *Account) SuggestedFriends() (SuggestedFriends, error) {
	body, err := acc.CasperClient.SuggestedFriends()
	if err != nil {
		return SuggestedFriends{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed SuggestedFriends
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// LoadLensSchedule fetches the lens schedule for the authenticated account.
// Not working as of now.
func (acc *Account) LoadLensSchedule() (LensSchedule, error) {
	body, err := acc.CasperClient.LoadLensSchedule()
	if err != nil {
		return LensSchedule{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed LensSchedule
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// DiscoverChannels fetches Snapchat discover channels.
func (acc *Account) DiscoverChannels() (Discover, error) {
	body, err := acc.CasperClient.DiscoverChannels()
	if err != nil {
		return Discover{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed Discover
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// DownloadSnapTag fetches the authenticated users Snaptag.
// Note: calls acc.Update() to get authenticated users SnapTag if acc.UserID is not set.
func (acc *Account) DownloadSnapTag(sfmt SnapTagImageFormat) (SnapTag, error) {
	if acc.UserID == "" {
		updates, err := acc.Updates()
		if err != nil {
			return SnapTag{}, err
		}
		acc.UserID = updates.UpdatesResponse.UserID
	}

	format := string(sfmt)
	body, err := acc.CasperClient.DownloadSnapTag(acc.UserID, format)
	if err != nil {
		return SnapTag{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed SnapTag
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// DownloadFriendSnapTag fetches a friends Snaptag.
// Requires their Snapchat user_id in the form:
// 84ee8839-3911-492d-8b94-72dd80f3713a
func (acc *Account) DownloadFriendSnapTag(userID string, sfmt SnapTagImageFormat) (SnapTag, error) {
	format := string(sfmt)
	body, err := acc.CasperClient.DownloadSnapTag(userID, format)
	if err != nil {
		return SnapTag{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed SnapTag
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// Upload sends media to Snapchat.
func (acc *Account) Upload(path string) (string, error) {
	id := MediaID(acc.Username)
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return "", errors.New("File does not exist.")
	}
	mediaType, err := DetectMedia(file)
	if err != nil {
		return "", err
	}
	options, err := acc.CasperClient.Upload()
	if err != nil {
		return "", err
	}
	data := map[string]string{
		"media_id":  id,
		"req_token": options.Params["req_token"],
		"timestamp": options.Params["timestamp"],
		"type":      mediaType,
		"username":  acc.Username,
		"zipped":    "0",
	}
	resp := acc.SendMultipartRequest("/ph/upload", data, path, options)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	if resp.StatusCode != 200 {
		return "", errors.New("An error occured: HTTP Status: " + resp.Status)
	}
	return id, nil
}

// Send sends media to other Snapchat users.
func (acc *Account) Send(mediaID string, recipients []string, time int) (map[string]interface{}, error) {
	body, err := acc.CasperClient.Send(mediaID, recipients, time)
	if err != nil {
		return nil, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// RetrySend retries to resend media to Snapchat users.
func (acc *Account) RetrySend(mediaID string, path string, recipients []string, time int) (map[string]interface{}, error) {
	ts := Timestamp()
	var rp string
	for i, v := range recipients {
		if i > 0 {
			rp += "\",\""
		} else {
			rp += "[\""
		}
		rp += v
		if i == len(recipients)-1 {
			rp += "\"]"
		}
	}
	timeString := strconv.Itoa(time)
	data := map[string]string{
		"username":            acc.Username,
		"timestamp":           ts,
		"req_token":           RequestToken(acc.Token, ts),
		"media_id":            mediaID,
		"recipients":          string(rp),
		"reply":               "0",
		"time":                timeString,
		"camera_front_facing": "0",
		"zipped":              "0",
	}
	options, err := acc.CasperClient.RetrySend()
	if err != nil {
		return nil, err
	}
	resp := acc.SendMultipartRequest("/loq/retry", data, path, options)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		return nil, ioErr
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("An error occured: HTTP Status: " + resp.Status)
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// Stories fetches the current users Snapchat stories.
// Useful if you only want the Snapchat stories.
func (acc *Account) Stories() (casper.Stories, error) {
	body, err := acc.CasperClient.Stories()
	if err != nil {
		return casper.Stories{}, err
	}
	return body, nil
}

// PostStory posts media to a users Snapchat story.
func (acc *Account) PostStory(mediaID string, path string, caption string, time int) (StorySnap, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return StorySnap{}, errors.New("File does not exist.")
	}
	mediaType, err := DetectMedia(file)
	if err != nil {
		return StorySnap{}, err
	}
	if caption == "" {
		caption = ""
	}
	body, err := acc.CasperClient.PostStory(mediaID, caption, time, mediaType)
	if err != nil {
		return StorySnap{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed StorySnap
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// RetryPostStory retries to post media to a users Snapchat story.
func (acc *Account) RetryPostStory(path string, caption string, time int) (StorySnap, error) {
	ts := Timestamp()
	id := MediaID(acc.Username)
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return StorySnap{}, errors.New("File does not exist.")
	}
	mediaType, err := DetectMedia(file)
	if err != nil {
		return StorySnap{}, err
	}
	if caption == "" {
		caption = ""
	}
	options, err := acc.CasperClient.RetryPostStory()
	if err != nil {
		return StorySnap{}, err
	}
	timeString := strconv.Itoa(int(time))
	data := map[string]string{
		"camera_front_facing": "0",
		"orientation":         "0",
		"username":            acc.Username,
		"req_token":           options.Params["req_token"],
		"timestamp":           options.Params["timestamp"],
		"story_timestamp":     ts,
		"media_id":            id,
		"client_id":           id,
		"zipped":              "0",
		"type":                mediaType,
		"time":                timeString,
	}
	resp := acc.SendMultipartRequest("/bq/retry_post_story", data, path, options)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		return StorySnap{}, ioErr
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	if resp.StatusCode != 202 {
		return StorySnap{}, errors.New("An error occured: HTTP Status: " + resp.Status)
	}
	var parsed StorySnap
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// DeleteStory deletes media from a Snapchat story.
func (acc *Account) DeleteStory(id string) error {
	err := acc.CasperClient.DeleteStory(id)
	if err != nil {
		return err
	}
	return nil
}

// DoublePost posts a snap to a users Snapchat story and to other Snapchat users.
func (acc *Account) DoublePost(path string, recipients []string, caption string, time int) (StorySnapFull, error) {
	ts := Timestamp()
	var rp string
	for i, v := range recipients {
		if i > 0 {
			rp += "\",\""
		} else {
			rp += "[\""
		}
		rp += v
		if i == len(recipients)-1 {
			rp += "\"]"
		}
	}
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return StorySnapFull{}, errors.New("File does not exist.")
	}
	mediaType, err := DetectMedia(file)
	if err != nil {
		return StorySnapFull{}, err
	}
	if caption == "" {
		caption = ""
	}
	id, err := acc.Upload(path)
	if err != nil {
		return StorySnapFull{}, err
	}
	options, err := acc.CasperClient.DoublePost()
	if err != nil {
		return StorySnapFull{}, err
	}
	data := map[string]string{
		"username":             acc.Username,
		"req_token":            options.Params["req_token"],
		"timestamp":            options.Params["timestamp"],
		"media_id":             id,
		"client_id":            id,
		"orientation":          "0",
		"reply":                "0",
		"recipients":           string(rp),
		"camera_front_facing":  "0",
		"story_timestamp":      ts,
		"caption_text_display": caption,
		"type":                 mediaType,
		"time":                 string(time),
		"zipped":               "0",
	}
	resp := acc.SendMultipartRequest("/loq/double_post", data, "", options)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		return StorySnapFull{}, ioErr
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed StorySnapFull
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// UserExists checks if a username exists in Snapchat.
func (acc *Account) UserExists(requestUsername string) (map[string]interface{}, error) {
	body, err := acc.CasperClient.UserExists(requestUsername)
	if err != nil {
		return nil, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// FindFriends finds friends using a phone number from contacts.
func (acc *Account) FindFriends(countryCode string, contacts map[string]string) (map[string]interface{}, error) {
	body, err := acc.CasperClient.FindFriends(countryCode, contacts)
	if err != nil {
		return nil, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// AddFriend adds a friend on Snapchat.
func (acc *Account) AddFriend(friend string) (Friend, error) {
	body, err := acc.CasperClient.Friend(friend, "add", "")
	if err != nil {
		return Friend{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed Friend
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// DeleteFriend deletes a friend on Snapchat.
func (acc *Account) DeleteFriend(friend string) (Friend, error) {
	body, err := acc.CasperClient.Friend(friend, "delete", "")
	if err != nil {
		return Friend{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed Friend
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// BlockFriend blocks a friend on Snapchat.
func (acc *Account) BlockFriend(friend string) (Friend, error) {
	body, err := acc.CasperClient.Friend(friend, "block", "")
	if err != nil {
		return Friend{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed Friend
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// UnblockFriend unblocks a friend on Snapchat.
func (acc *Account) UnblockFriend(friend string) (Friend, error) {
	body, err := acc.CasperClient.Friend(friend, "unblock", "")
	if err != nil {
		return Friend{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed Friend
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// SetNickname sets a nickname of a friend on Snapchat.
func (acc *Account) SetNickname(friend, nickname string) (Friend, error) {
	body, err := acc.CasperClient.Friend(friend, "display", nickname)
	if err != nil {
		return Friend{}, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed Friend
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// BestFriends fetches best friends and scores on Snapchat.
func (acc *Account) BestFriends(friends []string) (map[string]interface{}, error) {
	body, err := acc.CasperClient.BestFriends(friends)
	if err != nil {
		return nil, err
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// SetProxyURL sets given string addr, as a proxy addr. Primarily for debugging purposes.
// Other reasons include bypassing IP banning.
func (acc *Account) SetProxyURL(addr string) error {
	proxyURL, err := url.Parse(addr)
	if err != nil {
		return err
	}
	if proxyURL.Scheme == "" {
		return errors.New("Invalid proxy url.")
	}
	acc.ProxyURL = proxyURL
	acc.CasperClient.ProxyURL = proxyURL
	return nil
}
