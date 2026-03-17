package gpcm

import (
	"bufio"

	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"wwfc/common"
	"wwfc/database"
	"wwfc/logging"
	"wwfc/qr2"

	"github.com/logrusorgru/aurora/v3"
)

const (
	UnitCodeDS             = 0
	UnitCodeWii            = 1
	UnitCodeDSAndWii       = 0xff
	asnListFilename        = "ASN.txt"
	asnExtraFilename       = "ASN_EXTRA.txt"
	asnISPFilename         = "ASN_ISP.txt"
	asnConfigFilename      = "ASN.conf"
	asnIPInfoCacheFilename = "ASN_IPINFO.cache"
	deluxeBanPublicReason  = "Please disable your VPN/proxy, if you're not using a VPN/proxy, contact support and ask for a whitelist"
)

type MinimumPayloadVersion struct {
	major byte
	minor int
}

var MinimumPayloadVersions = []MinimumPayloadVersion{
	{
		major: 0,
		minor: 1,
	},
}

func generateResponse(gpcmChallenge, nasChallenge, authToken, clientChallenge string) string {
	hasher := md5.New()
	hasher.Write([]byte(nasChallenge))
	str := hex.EncodeToString(hasher.Sum(nil))
	str += strings.Repeat(" ", 48)
	str += authToken
	str += clientChallenge
	str += gpcmChallenge
	str += hex.EncodeToString(hasher.Sum(nil))

	_hasher := md5.New()
	_hasher.Write([]byte(str))
	return hex.EncodeToString(_hasher.Sum(nil))
}

func generateProof(gpcmChallenge, nasChallenge, authToken, clientChallenge string) string {
	return generateResponse(clientChallenge, nasChallenge, authToken, gpcmChallenge)
}

var msPublicKey = []byte{
	0x00, 0xFD, 0x56, 0x04, 0x18, 0x2C, 0xF1, 0x75, 0x09, 0x21, 0x00, 0xC3, 0x08, 0xAE, 0x48, 0x39,
	0x91, 0x1B, 0x6F, 0x9F, 0xA1, 0xD5, 0x3A, 0x95, 0xAF, 0x08, 0x33, 0x49, 0x47, 0x2B, 0x00, 0x01,
	0x71, 0x31, 0x69, 0xB5, 0x91, 0xFF, 0xD3, 0x0C, 0xBF, 0x73, 0xDA, 0x76, 0x64, 0xBA, 0x8D, 0x0D,
	0xF9, 0x5B, 0x4D, 0x11, 0x04, 0x44, 0x64, 0x35, 0xC0, 0xED, 0xA4, 0x2F,
}

var commonDeviceIds = []uint32{
	0x02000001, // Internal use
	0x0403ac68, // Dolphin default

	// Publicly shared key dumps
	0x02023f0a,
	0x0204cef9, // From RR
	0x038c864b,
	0x040e3f97,
	0x0411bbe5,
	0x04cb7515,
	0x066deb49,
	0x06bcc32d,
	0x06d0437a,
	0x0812f46b,
	0x089120c8,
	0x0a305428, // From RR
	0x0a447b97, // From RR
	0x0a1e97cf, // From RR
	0x0e19d5ed,
	0x0e31482b,
	0x2428a8cb,
	0x247dd10b,
}
var (
	ipinfoClient    = &http.Client{Timeout: 5 * time.Second}
	year3000Unix    = time.Now().Unix() //time.Date(3000, time.January, 1, 2, 0, 0, 0, time.UTC).Unix()
	ipinfoCache     map[string]ipinfoCacheEntry
	ipinfoCacheMu   sync.RWMutex
	ipinfoCacheOnce sync.Once
)

func verifySignature(moduleName string, authToken string, signature string) (defaultKey bool, result uint32) {
	result = 0
	defaultKey = false

	sigBytes, err := common.Base64DwcEncoding.DecodeString(signature)
	if err != nil || (len(sigBytes) != 0x144 && len(sigBytes) != 0x148) {
		return
	}

	ngId := sigBytes[0x000:0x004]

	if !allowDefaultDolphinKeys {
		// Skip authentication signature verification for common device IDs (the caller should handle this)
		for _, defaultDeviceId := range commonDeviceIds {
			if binary.BigEndian.Uint32(ngId) == defaultDeviceId {
				if !allowDefaultDolphinKeys {
					logging.Warn(moduleName, "Using default NG device ID")
				}
				result = defaultDeviceId
				defaultKey = true
				return
			}
		}
	}

	ngTimestamp := sigBytes[0x004:0x008]
	caId := sigBytes[0x008:0x00C]
	msId := sigBytes[0x00C:0x010]
	apId := sigBytes[0x010:0x018]
	msSignature := sigBytes[0x018:0x054]
	ngPublicKey := sigBytes[0x054:0x090]
	ngSignature := sigBytes[0x090:0x0CC]
	apPublicKey := sigBytes[0x0CC:0x108]
	apSignature := sigBytes[0x108:0x144]
	apTimestamp := []byte{0, 0, 0, 0}
	if len(sigBytes) == 0x148 {
		apTimestamp = sigBytes[0x144:0x148]
	}

	ngIssuer := fmt.Sprintf("Root-CA%02x%02x%02x%02x-MS%02x%02x%02x%02x", caId[0], caId[1], caId[2], caId[3], msId[0], msId[1], msId[2], msId[3])
	ngName := fmt.Sprintf("NG%02x%02x%02x%02x", ngId[0], ngId[1], ngId[2], ngId[3])

	ngCertBlob := []byte(ngIssuer)
	ngCertBlob = append(ngCertBlob, make([]byte, 0x40-len(ngIssuer))...)
	ngCertBlob = append(ngCertBlob, 0x00, 0x00, 0x00, 0x02)
	ngCertBlob = append(ngCertBlob, []byte(ngName)...)
	ngCertBlob = append(ngCertBlob, make([]byte, 0x40-len(ngName))...)
	ngCertBlob = append(ngCertBlob, ngTimestamp...)
	ngCertBlob = append(ngCertBlob, ngPublicKey...)
	ngCertBlob = append(ngCertBlob, make([]byte, 0x3C)...)
	ngCertBlobHash := sha1.Sum(ngCertBlob)

	if !verifyECDSA(msPublicKey, msSignature, ngCertBlobHash[:]) {
		logging.Error(moduleName, "NG cert verify failed")
		return
	}
	logging.Info(moduleName, "NG cert verified")

	apIssuer := ngIssuer + "-" + ngName
	apName := fmt.Sprintf("AP%02x%02x%02x%02x%02x%02x%02x%02x", apId[0], apId[1], apId[2], apId[3], apId[4], apId[5], apId[6], apId[7])

	apCertBlob := []byte(apIssuer)
	apCertBlob = append(apCertBlob, make([]byte, 0x40-len(apIssuer))...)
	apCertBlob = append(apCertBlob, 0x00, 0x00, 0x00, 0x02)
	apCertBlob = append(apCertBlob, []byte(apName)...)
	apCertBlob = append(apCertBlob, make([]byte, 0x40-len(apName))...)
	apCertBlob = append(apCertBlob, apTimestamp...)
	apCertBlob = append(apCertBlob, apPublicKey...)
	apCertBlob = append(apCertBlob, make([]byte, 0x3C)...)
	apCertBlobHash := sha1.Sum(apCertBlob)

	if !verifyECDSA(ngPublicKey, ngSignature, apCertBlobHash[:]) {
		logging.Error(moduleName, "AP cert verify failed")
		return
	}
	logging.Info(moduleName, "AP cert verified")

	authTokenHash := sha1.Sum([]byte(authToken))
	if !verifyECDSA(apPublicKey, apSignature, authTokenHash[:]) {
		logging.Error(moduleName, "Auth token signature failed")
		return
	}
	logging.Notice(moduleName, "Auth token signature verified; NG ID:", aurora.Cyan(fmt.Sprintf("%08x", ngId)))

	result = binary.BigEndian.Uint32(ngId)
	return
}

func (g *GameSpySession) login(command common.GameSpyCommand) {
	if g.LoggedIn {
		logging.Error(g.ModuleName, "Attempt to login twice")
		g.replyError(ErrLogin)
		return
	}

	authToken := command.OtherValues["authtoken"]
	if authToken == "" {
		g.replyError(ErrLogin)
		return
	}

	gamecd, issueTime, userId, gsbrcd, cfc, region, lang, ingamesn, challenge, unitcd, isLocalhost, err := common.UnmarshalNASAuthToken(authToken)
	if err != nil {
		g.replyError(ErrLogin)
		return
	}

	currentTime := time.Now().UTC()
	if issueTime.Before(currentTime.Add(-10*time.Minute)) || issueTime.After(currentTime) {
		g.replyError(ErrLoginLoginTicketExpired)
		return
	}

	g.GameName = command.OtherValues["gamename"]
	logging.Info(g.ModuleName, "Game name:", aurora.Cyan(g.GameName))
	g.GameCode = gamecd
	g.Region = region
	g.Language = lang
	g.ConsoleFriendCode = cfc
	g.InGameName = ingamesn
	g.UnitCode = unitcd
	var payloadVerExists bool
	if command.OtherValues["wwfc_ver"] != "" {
		_, payloadVerExists = command.OtherValues["wwfc_ver"]
	} else {
		_, payloadVerExists = command.OtherValues["wl:ver"]
	}
	logging.Notice("PayloadVerExists: " + strconv.FormatBool(payloadVerExists))
	_, signatureExists := command.OtherValues["wl:sig"]
	logging.Notice("signatureExists: " + strconv.FormatBool(signatureExists))
	deviceId := uint32(0)
	g.csnum = ""

	//if csnum, exists := command.OtherValues["wwfc_csnum"]; exists {
	if wsn, exists := command.OtherValues["wsn"]; exists {
		csnum, err := common.Base64DwcEncoding.DecodeString(wsn)
		if err != nil {
			logging.Error("Bad WSN conversion for PID: " + strconv.FormatUint(uint64(g.User.ProfileId), 10))
			g.replyError(ErrLoginBadPreAuth)
			return
		}
		g.csnum = strings.TrimRight(string(csnum), "\x00")
		if len(g.csnum) > 16 { // Picked a random length. Serial numbers appear to be anywhere from 9-12?
			logging.Error("invalid csnum for PID: " + strconv.FormatUint(uint64(g.User.ProfileId), 10))
			g.replyError(ErrLoginBadPreAuth)
			return
		}
	}

	if command.OtherValues["wwfc_host"] != "" {
		command.OtherValues["wl:host"] = command.OtherValues["wwfc_host"]
	}
	if hostPlatform, exists := command.OtherValues["wl:host"]; exists {
		g.HostPlatform = hostPlatform
	} else {
		if g.UnitCode == UnitCodeDS {
			g.HostPlatform = "DS"
		} else {
			g.HostPlatform = "Wii"
		}
	}

	g.LoginInfoSet = true

	expectedUnitCode := common.GetExpectedUnitCode(g.GameName)
	if (g.UnitCode != UnitCodeDS && g.UnitCode != UnitCodeWii) || (g.UnitCode != expectedUnitCode && expectedUnitCode != UnitCodeDSAndWii) {
		logging.Error(g.ModuleName, "Incorrect unit code specified:", aurora.Cyan(unitcd))
		g.replyError(ErrLogin)
		return
	}

	deviceAuth := false
	defaultKey := false
	if g.UnitCode == UnitCodeWii {
		if isLocalhost && !payloadVerExists { // && !payloadVerExists && !signatureExists {
			// Players using the DNS, need patching using a QR2 exploit
			if !common.DoesGameNeedExploit(g.GameName) {
				logging.Error(g.ModuleName, "Using DNS for incompatible game:", aurora.Cyan(g.GameName))
				g.replyError(GPError{
					ErrorCode:   ErrLogin.ErrorCode,
					ErrorString: "The client is not patched to use WiiLink WFC.",
					Fatal:       true,
				})
				return
			}

			g.NeedsExploit = true
			deviceAuth = false
		} else {
			//defaultKey, deviceId = g.verifyExLoginInfo(command, authToken)
			if deviceId == 0 {
				deviceAuth = true //	return
			}
			deviceAuth = true
		}
	} else if g.UnitCode == UnitCodeDS {
		g.NeedsExploit = common.DoesGameNeedExploit(g.GameName)
		deviceAuth = true
	} else {
		logging.Error(g.ModuleName, "Invalid unit code specified:", aurora.Cyan(unitcd))
		g.replyError(ErrLogin)
		return
	}

	response := generateResponse(g.Challenge, challenge, authToken, command.OtherValues["challenge"])
	if response != command.OtherValues["response"] {
		g.replyError(ErrLogin)
		return
	}

	proof := generateProof(g.Challenge, challenge, command.OtherValues["authtoken"], command.OtherValues["challenge"])

	cmdProfileId := uint32(0)
	if cmdProfileIdStr, exists := command.OtherValues["profileid"]; exists {
		cmdProfileId2, err := strconv.ParseUint(cmdProfileIdStr, 10, 32)
		if err != nil {
			g.replyError(GPError{
				ErrorCode:   ErrLogin.ErrorCode,
				ErrorString: "The provided profile ID is invalid.",
				Fatal:       true,
				WWFCMessage: WWFCMsgUnknownLoginError,
			})
			return
		}

		cmdProfileId = uint32(cmdProfileId2)
	}

	if !g.performLoginWithDatabase(userId, gsbrcd, cmdProfileId, defaultKey, deviceId, deviceAuth) {
		return
	}

	g.ModuleName = "GPCM:" + strconv.FormatInt(int64(g.User.ProfileId), 10) + "*"
	g.ModuleName += "/" + common.CalcFriendCodeString(g.User.ProfileId, g.User.GsbrCode[:4]) + "*"

	// Check to see if a session is already open with this profile ID
	mutex.Lock()
	otherSession, exists := sessions[g.User.ProfileId]
	if exists {
		otherSession.replyError(ErrForcedDisconnect)

		for i := 0; ; i++ {
			mutex.Unlock()
			time.Sleep(300 * time.Millisecond)
			mutex.Lock()

			if _, exists = sessions[g.User.ProfileId]; !exists {
				break
			}

			// Give up after 6 seconds
			if i >= 20 {
				mutex.Unlock()
				logging.Error(g.ModuleName, "Failed to disconnect other session")
				g.replyError(ErrForcedDisconnect)
				return
			}
		}
	}
	sessions[g.User.ProfileId] = g
	mutex.Unlock()

	g.AuthToken = authToken
	g.LoginTicket = common.MarshalGPCMLoginTicket(g.User.ProfileId)
	g.SessionKey = rand.Int31n(290000000) + 10000000

	g.DeviceAuthenticated = deviceAuth
	g.LoggedIn = true
	g.ModuleName = "GPCM:" + strconv.FormatInt(int64(g.User.ProfileId), 10)
	g.ModuleName += "/" + common.CalcFriendCodeString(g.User.ProfileId, g.User.GsbrCode[:4])
	ctgpver := "NOTPEDO" //DD
	// Notify QR2 of the login

	banvpn, err := database.DoesUserVPNWhitelist(pool, ctx, g.User.ProfileId)

	if err != nil {
		logging.Error(g.ModuleName, "Error checking VPN whitelist:", err)
	}

	if g.csnum != "" { //ignore if csnum is blank for other distros, but would deny matchmaking if not present for deluxe in DXWW
		ok, whitelisted, err := database.Checkcsnum(pool, ctx, g.User.ProfileId, g.csnum)
		if err != nil {
			logging.Notice("DB error with csnum for PID: " + strconv.FormatUint(uint64(g.User.ProfileId), 10))
			g.replyError(ErrLoginBadPreAuth)
			return
		}
		if !ok && !whitelisted {
			g.csnum = "0"
			//g.replyError(ErrLoginBadPreAuth)
			//return
		}

		//ok, err := database.Checkcsnumban(pool, ctx, g.User.ProfileId, g.csnum)
	}

	g.User.DeluxeBan = false
	g.User.BanLenght = int64(0)
	g.User.Public_reason = ""
	g.User.DeluxeBan, g.User.BanLenght, g.User.Public_reason, err = database.DoesUserDeluxeBanCheck(pool, ctx, g.User.ProfileId, g.RemoteAddr, g.csnum)
	if err != nil {
		g.replyError(ErrLoginBadPreAuth)
		return
	}

	if !banvpn && !g.User.DeluxeBan {
		config := common.GetConfig()
		g.applyASNDeluxeBan(config.IpinfoToken)
		if g.User.DeluxeBan {
			logging.Warn(g.ModuleName, "Deluxe ban applied due to ASN/VPN blocklist for user ", aurora.Red(g.User.ProfileId), " ", aurora.Red(ingamesn))
		}
	}

	qr2.Login(g.User.ProfileId, gamecd, ingamesn, cfc, g.User.GsbrCode[:4], g.RemoteAddr, g.NeedsExploit, g.DeviceAuthenticated, g.User.Restricted, g.User.Trusted, g.User.OpenHost, ctgpver, g.User.DeluxeBan, g.User.BanLenght, g.csnum) //Deluxeban
	//qr2.Login(g.User.ProfileId, gamecd, ingamesn, cfc, g.User.GsbrCode[:4], g.RemoteAddr, g.NeedsExploit, g.DeviceAuthenticated, g.User.Restricted)

	replyUserId := g.User.UserId
	if g.UnitCode == UnitCodeDS {
		// Workaround for SDK bug
		replyUserId = 0
	}

	otherValues := map[string]string{
		"sesskey":    strconv.FormatInt(int64(g.SessionKey), 10),
		"proof":      proof,
		"userid":     strconv.FormatUint(replyUserId, 10),
		"profileid":  strconv.FormatUint(uint64(g.User.ProfileId), 10),
		"uniquenick": g.User.UniqueNick,
		"lt":         g.LoginTicket,
		"id":         command.OtherValues["id"],
	}

	if g.GameName == "mariokartwii" {
		if motd, err := GetMessageOfTheDay(); err != nil {
			logging.Info(g.ModuleName, err)
		} else {
			motdUTF16 := utf16.Encode([]rune(motd))
			motdByteArray := common.UTF16ToByteArray(motdUTF16)
			otherValues["wwfc_motd"] = common.Base64DwcEncoding.EncodeToString(motdByteArray)
			//otherValues["wl:motd"] = common.Base64DwcEncoding.EncodeToString(motdByteArray)
		}
	}

	payload := common.CreateGameSpyMessage(common.GameSpyCommand{
		Command:      "lc",
		CommandValue: "2",
		OtherValues:  otherValues,
	})

	common.SendPacket(ServerName, g.ConnIndex, []byte(payload))
}

func (g *GameSpySession) exLogin(command common.GameSpyCommand) {
	if !g.LoggedIn {
		logging.Warn(g.ModuleName, "Ignoring exlogin before login")
		return
	}

	defaultKey, deviceId := g.verifyExLoginInfo(command, g.AuthToken)
	if deviceId == 0 {
		return
	}

	if !g.performLoginWithDatabase(g.User.UserId, g.User.GsbrCode, 0, defaultKey, deviceId, true) {
		return
	}

	g.DeviceAuthenticated = true
	qr2.SetDeviceAuthenticated(g.User.ProfileId)
}

func checkPayloadVersion(payloadVer string) bool {
	verInt, err := strconv.ParseInt(payloadVer, 0, 32)
	if err != nil {
		return false
	}

	major := byte(verInt>>24) & 255
	minor := int(verInt>>12) & 4095
	// beta := verInt & 4095

	for _, v := range MinimumPayloadVersions {
		if v.major == major && minor >= v.minor {
			return true
		}
	}
	return false
}

func (g *GameSpySession) verifyExLoginInfo(command common.GameSpyCommand, authToken string) (defaultKey bool, deviceId uint32) {
	payloadVer, payloadVerExists := command.OtherValues["payload_ver"]
	signature, signatureExists := command.OtherValues["wwfc_sig"]
	defaultKey = false
	deviceId = 0

	if !payloadVerExists || payloadVer != "4" { //!checkPayloadVersion(payloadVer) {
		g.replyError(GPError{
			ErrorCode:   ErrLogin.ErrorCode,
			ErrorString: "The payload version is invalid.",
			Fatal:       true,
			WWFCMessage: WWFCMsgPayloadInvalid,
		})
		return
	}

	if !signatureExists {
		g.replyError(GPError{
			ErrorCode:   ErrLogin.ErrorCode,
			ErrorString: "Missing authentication signature.",
			Fatal:       true,
			WWFCMessage: WWFCMsgUnknownLoginError,
		})
		return
	}

	defaultKey, deviceId = verifySignature(g.ModuleName, authToken, signature)
	if deviceId == 0 {
		g.replyError(GPError{
			ErrorCode:   ErrLogin.ErrorCode,
			ErrorString: "The authentication signature is invalid.",
			Fatal:       true,
			WWFCMessage: WWFCMsgUnknownLoginError,
		})
		return
	}

	g.DeviceId = deviceId
	return
}

func (g *GameSpySession) performLoginWithDatabase(userId uint64, gsbrCode string, profileId uint32, defaultKey bool, deviceId uint32, deviceAuth bool) bool {
	// Get IP address without port
	ipAddress := g.RemoteAddr
	if strings.Contains(ipAddress, ":") {
		ipAddress = ipAddress[:strings.Index(ipAddress, ":")]
	}

	user, err := database.LoginUserToGPCM(pool, ctx, userId, gsbrCode, profileId, defaultKey, deviceId, ipAddress, g.InGameName, deviceAuth)
	g.User = user

	if err != nil {
		logging.Error(g.ModuleName, "DB error:", err)

		if err == database.ErrProfileIDInUse {
			g.replyError(GPError{
				ErrorCode:   ErrLogin.ErrorCode,
				ErrorString: "The profile ID is already in use.",
				Fatal:       true,
				WWFCMessage: WWFCMsgProfileIDInUse,
			})
		} else if err == database.ErrReservedProfileIDRange {
			g.replyError(GPError{
				ErrorCode:   ErrLogin.ErrorCode,
				ErrorString: "The profile ID is in a reserved range.",
				Fatal:       true,
				WWFCMessage: WWFCMsgProfileIDInvalid,
			})
		} else if err == database.ErrDeviceIDMismatch {
			if strings.HasPrefix(g.HostPlatform, "Dolphin") {
				g.replyError(GPError{
					ErrorCode:   ErrLogin.ErrorCode,
					ErrorString: "The device ID does not match the one on record.",
					Fatal:       true,
					WWFCMessage: WWFCMsgConsoleMismatchDolphin,
				})
			} else {
				g.replyError(GPError{
					ErrorCode:   ErrLogin.ErrorCode,
					ErrorString: "The device ID does not match the one on record.",
					Fatal:       true,
					WWFCMessage: WWFCMsgConsoleMismatch,
				})
			}
		} else if err == database.ErrProhibitedDeviceID {
			if strings.HasPrefix(g.HostPlatform, "Dolphin") {
				g.replyError(GPError{
					ErrorCode:   ErrLogin.ErrorCode,
					ErrorString: "Prohibited device ID used in signature.",
					Fatal:       true,
					WWFCMessage: WWFCMsgDolphinSetupRequired,
				})
			} else {
				g.replyError(GPError{
					ErrorCode:   ErrLogin.ErrorCode,
					ErrorString: "Prohibited device ID used in signature.",
					Fatal:       true,
					WWFCMessage: WWFCMsgUnknownLoginError,
				})
			}
		} else if err == database.ErrProfileBannedTOS {
			g.replyError(GPError{
				ErrorCode:   ErrLogin.ErrorCode,
				ErrorString: "The profile is banned from the service. Reason: " + user.BanReason,
				Fatal:       true,
				WWFCMessage: WWFCMsgProfileBannedTOS,
				Reason:      user.BanReason,
			})
		} else {
			g.replyError(GPError{
				ErrorCode:   ErrLogin.ErrorCode,
				ErrorString: "There was an error logging in to the GP backend.",
				Fatal:       true,
				WWFCMessage: WWFCMsgUnknownLoginError,
			})
		}

		return false
	}

	return true
}

func IsLoggedIn(profileID uint32) bool {
	mutex.Lock()
	defer mutex.Unlock()

	session, exists := sessions[profileID]
	return exists && session.LoggedIn
}

type ipinfoCacheEntry struct {
	IsAnonymous bool
	IsHosting   bool
	IsAnycast   bool
}

func (entry ipinfoCacheEntry) isSuspicious() bool {
	return entry.IsAnonymous || entry.IsHosting || entry.IsAnycast
}

type ipinfoLookupResponse struct {
	IP  string `json:"ip"`
	Org string `json:"org"`
	ASN string `json:"asn"`
	Geo struct {
		City          string  `json:"city"`
		Region        string  `json:"region"`
		RegionCode    string  `json:"region_code"`
		Country       string  `json:"country"`
		CountryCode   string  `json:"country_code"`
		Continent     string  `json:"continent"`
		ContinentCode string  `json:"continent_code"`
		Latitude      float64 `json:"latitude"`
		Longitude     float64 `json:"longitude"`
		Timezone      string  `json:"timezone"`
		PostalCode    string  `json:"postal_code"`
	} `json:"geo"`
	AS struct {
		ASN    string `json:"asn"`
		Name   string `json:"name"`
		Domain string `json:"domain"`
		Type   string `json:"type"`
	} `json:"as"`
	IsAnonymous *bool `json:"is_anonymous"`
	IsHosting   *bool `json:"is_hosting"`
	IsAnycast   *bool `json:"is_anycast"`
	IsMobile    *bool `json:"is_mobile"`
	IsSatellite *bool `json:"is_satellite"`
}

func (r ipinfoLookupResponse) toCacheEntry() (ipinfoCacheEntry, bool) {
	entry := ipinfoCacheEntry{
		IsAnonymous: boolValue(r.IsAnonymous),
		IsHosting:   boolValue(r.IsHosting),
		IsAnycast:   boolValue(r.IsAnycast),
	}
	hasFlags := r.IsAnonymous != nil || r.IsHosting != nil || r.IsAnycast != nil
	return entry, hasFlags
}

func (g *GameSpySession) applyASNDeluxeBan(token string) {
	if token == "" {
		return
	}
	ip := stripPort(g.RemoteAddr)
	if ip == "" {
		logging.Warn(g.ModuleName, "Unable to determine IP address for ASN check")
		return
	}
	if parsed := net.ParseIP(ip); parsed == nil {
		logging.Warn(g.ModuleName, "Invalid IP address for ASN check:", ip)
		return
	}
	if entry, ok := getCachedIPInfo(ip); ok {
		if entry.isSuspicious() {
			g.markDeluxeBan()
			logging.Warn(g.ModuleName, "Automatic deluxe ban applied from cache", aurora.Red(ip))
		}
		return
	}
	asn, entry, hasFlags, err := fetchASNAndFlagsFromIPInfo(ip, token)
	if err != nil {
		logging.Warn(g.ModuleName, "IPInfo lookup failed:", err)
		return
	}
	if hasFlags {
		cacheIPInfoFlags(ip, entry)
		if entry.isSuspicious() {
			g.markDeluxeBan()
			logging.Warn(g.ModuleName, "Automatic deluxe ban applied from IPInfo flags", aurora.Red(ip))
		}
		return
	}
	if asn == "" {
		return
	}
	bl, err := loadASNBlocklist()
	if err != nil {
		logging.Error(g.ModuleName, "Failed to load ASN blocklist:", err)
		return
	}
	if _, blocked := bl[asn]; blocked {
		g.markDeluxeBan()
		logging.Warn(g.ModuleName, "Automatic deluxe ban applied for ASN", aurora.Red(asn))
	}
}

func (g *GameSpySession) markDeluxeBan() {
	g.User.DeluxeBan = true
	g.User.BanLenght = year3000Unix
	g.User.Public_reason = deluxeBanPublicReason
}

func fetchASNAndFlagsFromIPInfo(ip, token string) (string, ipinfoCacheEntry, bool, error) {
	url := fmt.Sprintf("https://api.ipinfo.io/lookup/%s?token=%s", ip, token)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", ipinfoCacheEntry{}, false, err
	}
	resp, err := ipinfoClient.Do(req)
	if err != nil {
		return "", ipinfoCacheEntry{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ipinfoCacheEntry{}, false, fmt.Errorf("ipinfo responded with status %s", resp.Status)
	}
	var data ipinfoLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", ipinfoCacheEntry{}, false, err
	}
	asn := strings.ToUpper(strings.TrimSpace(data.ASN))
	if asn == "" {
		asn = strings.ToUpper(strings.TrimSpace(data.AS.ASN))
	}
	if asn == "" {
		fields := strings.Fields(data.Org)
		if len(fields) > 0 {
			asn = strings.ToUpper(fields[0])
		}
	}
	entry, hasFlags := data.toCacheEntry()
	return asn, entry, hasFlags, nil
}

func loadASNBlocklist() (map[string]struct{}, error) {
	m := make(map[string]struct{})
	files := []string{asnListFilename, asnExtraFilename}
	if shouldIncludeISPASN() {
		files = append(files, asnISPFilename)
	}
	for _, filename := range files {
		if err := loadASNFileInto(m, filename); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
	}
	return m, nil
}

func stripPort(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	if idx := strings.LastIndex(remoteAddr, ":"); idx > 0 {
		return remoteAddr[:idx]
	}
	return remoteAddr
}

func loadASNFileInto(m map[string]struct{}, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		asn := strings.ToUpper(fields[0])
		if !strings.HasPrefix(asn, "AS") {
			continue
		}
		m[asn] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func shouldIncludeISPASN() bool {
	file, err := os.Open(asnConfigFilename)
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if lower == "true" || lower == "1" || lower == "yes" {
			return true
		}
		if strings.Contains(lower, "=") {
			parts := strings.SplitN(lower, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key == "enable_isp_block" || key == "block_isp" || key == "block_asn_isp" || key == "isp" {
				if value == "true" || value == "1" || value == "yes" {
					return true
				}
			}
		}
	}
	return false
}

func ensureIPInfoCacheLoaded() {
	ipinfoCacheOnce.Do(func() {
		ipinfoCache = make(map[string]ipinfoCacheEntry)
		file, err := os.Open(asnIPInfoCacheFilename)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				logging.Warn("GPCM", "failed to open IPInfo cache:", err)
			}
			return
		}
		defer file.Close()
		if err := gob.NewDecoder(file).Decode(&ipinfoCache); err != nil && err != io.EOF {
			logging.Warn("GPCM", "failed to decode IPInfo cache:", err)
			ipinfoCache = make(map[string]ipinfoCacheEntry)
		}
	})
}

func getCachedIPInfo(ip string) (ipinfoCacheEntry, bool) {
	ensureIPInfoCacheLoaded()
	ipinfoCacheMu.RLock()
	entry, ok := ipinfoCache[ip]
	ipinfoCacheMu.RUnlock()
	return entry, ok
}

func cacheIPInfoFlags(ip string, entry ipinfoCacheEntry) {
	ensureIPInfoCacheLoaded()
	ipinfoCacheMu.Lock()
	defer ipinfoCacheMu.Unlock()
	ipinfoCache[ip] = entry
	if err := saveIPInfoCacheLocked(); err != nil {
		logging.Warn("GPCM", "failed to persist IPInfo cache:", err)
	}
}

func saveIPInfoCacheLocked() error {
	file, err := os.Create(asnIPInfoCacheFilename)
	if err != nil {
		return err
	}
	defer file.Close()
	return gob.NewEncoder(file).Encode(ipinfoCache)
}

func boolValue(flag *bool) bool {
	return flag != nil && *flag
}
