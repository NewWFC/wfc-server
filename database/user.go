package database

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"
	"wwfc/logging"

	"github.com/jackc/pgx/v4/pgxpool"
)

const (
	InsertUser              = `INSERT INTO users (user_id, gsbrcd, password, ng_device_id, email, unique_nick) VALUES ($1, $2, $3, $4, $5, $6) RETURNING profile_id`
	InsertUserWithProfileID = `INSERT INTO users (profile_id, user_id, gsbrcd, password, ng_device_id, email, unique_nick) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	UpdateUserTable         = `UPDATE users SET firstname = CASE WHEN $3 THEN $2 ELSE firstname END, lastname = CASE WHEN $5 THEN $4 ELSE lastname END, open_host = CASE WHEN $7 THEN $6 ELSE open_host END WHERE profile_id = $1`
	UpdateUserProfileID     = `UPDATE users SET profile_id = $3 WHERE user_id = $1 AND gsbrcd = $2`
	UpdateUserNGDeviceID    = `UPDATE users SET ng_device_id = $2 WHERE profile_id = $1`
	GetUser                 = `SELECT user_id, gsbrcd, email, unique_nick, firstname, lastname, open_host, last_ip_address, last_ingamesn FROM users WHERE profile_id = $1`
	ClearProfileQuery       = `DELETE FROM users WHERE profile_id = $1 RETURNING user_id, gsbrcd, email, unique_nick, firstname, lastname, open_host, last_ip_address, last_ingamesn`
	DoesUserExist           = `SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1 AND gsbrcd = $2)`
	IsProfileIDInUse        = `SELECT EXISTS(SELECT 1 FROM users WHERE profile_id = $1)`
	DeleteUserSession       = `DELETE FROM sessions WHERE profile_id = $1`
	GetUserProfileID        = `SELECT profile_id, COALESCE(array_remove(ng_device_id, NULL), '{}'), email, unique_nick, firstname, lastname, open_host, last_ip_address FROM users WHERE user_id = $1 AND gsbrcd = $2`
	//GetUserProfileID        = `SELECT profile_id, ng_device_id, email, unique_nick, firstname, lastname, open_host, last_ip_address FROM users WHERE user_id = $1 AND gsbrcd = $2`
	//GetUserProfileID        = `SELECT profile_id, ng_device_id, email, unique_nick, firstname, lastname, open_host, last_ip_address, allow_default_keys FROM users WHERE user_id = $1 AND gsbrcd = $2`
	UpdateUserLastIPAddress = `UPDATE users SET last_ip_address = $2, last_ingamesn = $3 WHERE profile_id = $1`
	UpdateUserBan           = `UPDATE users SET has_ban = true, ban_issued = $2, ban_expires = $3, ban_reason = $4, ban_reason_hidden = $5, ban_moderator = $6, ban_tos = $7 WHERE profile_id = $1`
	DisableUserBan          = `UPDATE users SET has_ban = false WHERE profile_id = $1`

	GetMKWFriendInfoQuery    = `SELECT mariokartwii_friend_info FROM users WHERE profile_id = $1`
	UpdateMKWFriendInfoQuery = `UPDATE users SET mariokartwii_friend_info = $2 WHERE profile_id = $1`
	// UpdateUserBanDeluxe = `SELECT users WHERE profile_id = $1` //`UPDATE users SET has_ban = true, ban_issued = $2, ban_expires = $3, ban_reason = $4, ban_reason_hidden = $5, ban_moderator = $6, ban_tos = $7 WHERE profile_id = $1`
	UpdateUserBanDeluxe = `
WITH ensure_exists AS (
	INSERT INTO deluxeban (profile_id, hasban, ban_issued, ban_expires, ban_reason, ban_reason_hidden, ban_moderator, banned_ip, public_ban_reason, csnum)
	VALUES ($1, TRUE, $2, $3, $4, $5, $6, (SELECT last_ip_address FROM users WHERE profile_id = $1), $7, COALESCE((SELECT csnum FROM users WHERE profile_id = $1), ''))
	ON CONFLICT (profile_id) DO NOTHING
	RETURNING profile_id
),
ipaddress_cte AS (
	SELECT last_ip_address AS ip FROM users WHERE profile_id = $1
)
UPDATE deluxeban
SET 
	hasban = TRUE,
	ban_issued = $2,
	ban_expires = $3,
	ban_reason = $4,
	ban_reason_hidden = $5,
	ban_moderator = $6,
	banned_ip = (SELECT ip FROM ipaddress_cte),
	public_ban_reason = $7,
	csnum = COALESCE((SELECT csnum FROM users WHERE profile_id = $1), '')
WHERE profile_id = $1
   AND NOT EXISTS (SELECT 1 FROM ensure_exists);`

	DoesUserDeluxeBan = `
WITH matched_bans AS (
  SELECT * FROM deluxeban
  WHERE (profile_id = $1 OR banned_ip = $2)
	AND hasban = TRUE
),
latest_expire AS (
  SELECT MAX(ban_expires) AS max_expires
  FROM matched_bans
),
maybe_update AS (
  UPDATE deluxeban
  SET hasban = FALSE
  WHERE (profile_id = $1 OR banned_ip = $2)
	AND hasban = TRUE
	AND (SELECT max_expires FROM latest_expire) <= $3
)
SELECT 
	EXISTS (SELECT 1 FROM matched_bans) AS has_ban,
	COALESCE((SELECT EXTRACT(EPOCH FROM max_expires)::bigint FROM latest_expire), 0) AS ban_expires,
	COALESCE((SELECT public_ban_reason FROM matched_bans ORDER BY ban_expires DESC LIMIT 1), '') AS public_ban_reason;
  `

	DoesUserDeluxeBanAndcsnum = `
	WITH matched_bans AS (
		SELECT * FROM deluxeban
		WHERE (
			profile_id = $1
			OR banned_ip = $2
			OR (
				csnum IS NOT NULL
				AND regexp_replace(csnum, '[^0-9]', '', 'g') = regexp_replace($4, '[^0-9]', '', 'g')
			)
		)
		AND hasban = TRUE
	),
	latest_expire AS (
		SELECT MAX(ban_expires) AS max_expires
		FROM matched_bans
	),
	maybe_update AS (
		UPDATE deluxeban
		SET hasban = FALSE
		WHERE (
			profile_id = $1
			OR banned_ip = $2
			OR (
				csnum IS NOT NULL
				AND regexp_replace(csnum, '[^0-9]', '', 'g') = regexp_replace($4, '[^0-9]', '', 'g')
			)
		)
		AND hasban = TRUE
		AND (SELECT max_expires FROM latest_expire) <= $3
	)
	SELECT 
		EXISTS (SELECT 1 FROM matched_bans) AS has_ban,
		COALESCE((SELECT EXTRACT(EPOCH FROM max_expires)::bigint FROM latest_expire), 0) AS ban_expires,
		COALESCE((SELECT public_ban_reason FROM matched_bans ORDER BY ban_expires DESC LIMIT 1), '') AS public_ban_reason;
		`

	UpdateUserUnBanDeluxe = `
WITH ensure_exists AS (
	INSERT INTO deluxeban (profile_id)
	VALUES ($1)
	ON CONFLICT (profile_id) DO NOTHING
),
ipaddress_cte AS (
	SELECT last_ip_address AS ip FROM users WHERE profile_id = $1
),
update_profile AS (
	UPDATE deluxeban
	SET hasban = FALSE
	WHERE profile_id = $1
	RETURNING 1
),
update_ip AS (
	UPDATE deluxeban
	SET hasban = FALSE
	WHERE banned_ip = (SELECT ip FROM ipaddress_cte)
	RETURNING 1
),
csnum_cte AS (
	SELECT regexp_replace(csnum, '[^0-9]', '', 'g') AS normalized
	FROM users
	WHERE profile_id = $1
	AND csnum IS NOT NULL
),
update_csnum AS (
	UPDATE deluxeban
	SET hasban = FALSE
	WHERE csnum IS NOT NULL
	AND regexp_replace(csnum, '[^0-9]', '', 'g') = (SELECT normalized FROM csnum_cte)
	RETURNING 1
)
SELECT 1;
`

	Checkusercsnum  = `SELECT  COALESCE(csnum, '') AS csnum, csnumwhitelist FROM users WHERE profile_id = $1`
	Updateusercsnum = `UPDATE users SET csnum = $2 WHERE profile_id = $1`

	//WITH ipaddress AS (SELECT last_ip_address FROM users WHERE profile_id = $1)

	DoesUserExistTrusted = `SELECT EXISTS(SELECT 1 FROM trusted WHERE profile_id = $1)`
	FetchTrustedList     = `SELECT profile_id FROM trusted`
	FetchTrustedName     = `SELECT trusted.profile_id, COALESCE(users.last_ingamesn, 'empty') AS last_ingamesn, COALESCE(users.last_ip_address, 'empty') AS last_ip_address FROM trusted LEFT JOIN users ON trusted.profile_id = users.profile_id;`
	usernameapi          = `SELECT profile_id, COALESCE(last_ingamesn, 'empty') AS last_ingamesn, COALESCE(last_ip_address, 'empty') AS last_ip_address FROM users WHERE profile_id = $1`
	//GetUserTrusted = `SELECT  FROM trusted WHERE profile_id = $1` //PP db
	AddUserTrusted    = `INSERT INTO trusted (profile_id) VALUES ($1)`
	RemoveUserTrusted = `DELETE FROM trusted WHERE profile_id = $1`
	//VPN Whitelist
	DoesUserExistVPNWhitelist = `SELECT EXISTS(SELECT 1 FROM vpnwhitelist WHERE profile_id = $1)`
	DoesUsercsnumWhitelist    = `SELECT csnumwhitelist FROM users WHERE profile_id = $1`
	RemoveVPNWhitelist        = `DELETE FROM vpnwhitelist WHERE profile_id = $1`
	AddVPNWhitelist           = `INSERT INTO vpnwhitelist (profile_id, userid, moderator) VALUES ($1, $2, $3)`
	RemovecsnumWhitelist      = `UPDATE users SET csnumwhitelist = false WHERE profile_id = $1`
	AddcsnumWhitelist         = `UPDATE users SET csnumwhitelist = true WHERE profile_id = $1`
	FetchVPNWhitelistList     = `SELECT profile_id FROM vpnwhitelist`
	FetchVPNWhitelistName     = `SELECT vpnwhitelist.profile_id, COALESCE(users.last_ingamesn, 'empty') AS last_ingamesn, COALESCE(users.last_ip_address, 'empty') AS last_ip_address FROM vpnwhitelist LEFT JOIN users ON vpnwhitelist.profile_id = users.profile_id;`
)

type User struct {
	ProfileId          uint32
	UserId             uint64
	GsbrCode           string
	NgDeviceId         []int64 // stored as bigint[] in Postgres
	Email              string
	UniqueNick         string
	FirstName          string
	LastName           string
	Restricted         bool
	RestrictedDeviceId uint32
	BanReason          string
	OpenHost           bool
	LastInGameSn       string
	LastIPAddress      string
	Trusted            bool
	DeluxeBan          bool
	CTGPVER            string
	BanLenght          int64  // Duration of the ban in seconds
	Public_reason      string //public ban reason
	csnum              string
}

var (
	ErrProfileIDInUse         = errors.New("profile ID is already in use")
	ErrReservedProfileIDRange = errors.New("profile ID is in reserved range")
)

func (user *User) CreateUser(pool *pgxpool.Pool, ctx context.Context) error {
	if user.ProfileId == 0 {
		return pool.QueryRow(ctx, InsertUser, user.UserId, user.GsbrCode, "", user.NgDeviceId, user.Email, user.UniqueNick).Scan(&user.ProfileId)
	}

	if user.ProfileId >= 1000000000 {
		return ErrReservedProfileIDRange
	}

	var exists bool
	err := pool.QueryRow(ctx, IsProfileIDInUse, user.ProfileId).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		return ErrProfileIDInUse
	}

	_, err = pool.Exec(ctx, InsertUserWithProfileID, user.ProfileId, user.UserId, user.GsbrCode, "", user.NgDeviceId, user.Email, user.UniqueNick)
	return err
}

func (user *User) UpdateProfileID(pool *pgxpool.Pool, ctx context.Context, newProfileId uint32) error {
	if newProfileId >= 1000000000 {
		return ErrReservedProfileIDRange
	}

	var exists bool
	err := pool.QueryRow(ctx, IsProfileIDInUse, newProfileId).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		return ErrProfileIDInUse
	}

	_, err = pool.Exec(ctx, UpdateUserProfileID, user.UserId, user.GsbrCode, newProfileId)
	if err == nil {
		user.ProfileId = newProfileId
	}

	return err
}

func GetUniqueUserID() uint64 {
	// Not guaranteed unique but doesn't matter in practice if multiple people have the same user ID.
	return uint64(rand.Int63n(0x80000000000))
}

func (user *User) UpdateProfile(pool *pgxpool.Pool, ctx context.Context, data map[string]string) {
	firstName, firstNameExists := data["firstname"]
	lastName, lastNameExists := data["lastname"]
	openhostz := map[string]string{}
	if data["wl:oh"] != "" {
		openhostz["wwfc_openhost"] = data["wl:oh"]
	} else {
		openhostz["wwfc_openhost"] = data["wwfc_openhost"]
	}
	openHost, openHostExists := openhostz["wwfc_openhost"] //data["wwfc_openhost"] //["wl:oh"]
	openHostBool := false
	if openHostExists && openHost != "0" {
		openHostBool = true
	}

	_, err := pool.Exec(ctx, UpdateUserTable, user.ProfileId, firstName, firstNameExists, lastName, lastNameExists, openHostBool, openHostExists)
	if err != nil {
		panic(err)
	}

	if firstNameExists {
		user.FirstName = firstName
	}

	if lastNameExists {
		user.LastName = lastName
	}

	if openHostExists {
		user.OpenHost = openHostBool
	}
}

func GetProfile(pool *pgxpool.Pool, ctx context.Context, profileId uint32) (User, bool) {
	user := User{}
	row := pool.QueryRow(ctx, GetUser, profileId)
	err := row.Scan(&user.UserId, &user.GsbrCode, &user.Email, &user.UniqueNick, &user.FirstName, &user.LastName, &user.OpenHost, &user.LastIPAddress, &user.LastInGameSn)
	if err != nil {
		return User{}, false
	}

	user.ProfileId = profileId
	return user, true
}

func ClearProfile(pool *pgxpool.Pool, ctx context.Context, profileId uint32) (User, bool) {
	user := User{}
	row := pool.QueryRow(ctx, ClearProfileQuery, profileId)
	err := row.Scan(&user.UserId, &user.GsbrCode, &user.Email, &user.UniqueNick, &user.FirstName, &user.LastName, &user.OpenHost, &user.LastIPAddress, &user.LastInGameSn)

	if err != nil {
		return User{}, false
	}

	user.ProfileId = profileId
	return user, true
}

func BanUser(pool *pgxpool.Pool, ctx context.Context, profileId uint32, tos bool, length time.Duration, reason string, reasonHidden string, moderator string) bool {
	_, err := pool.Exec(ctx, UpdateUserBan, profileId, time.Now().UTC(), time.Now().UTC().Add(length), reason, reasonHidden, moderator, tos)
	return err == nil
}

func BanUserDeluxe(pool *pgxpool.Pool, ctx context.Context, profileId uint32, length time.Duration, reason string, reasonHidden string, moderator string, publicReason string) (bool, string) {
	result := ""
	_, err := pool.Exec(ctx, UpdateUserBanDeluxe, profileId, time.Now(), time.Now().Add(length), reason, reasonHidden, moderator, publicReason)
	if err != nil {
		result = err.Error()
		return false, result // false = operation failed
	}
	return true, result // true = operation succeeded
}
func UnBanUserDeluxe(pool *pgxpool.Pool, ctx context.Context, profileId uint32) (bool, string) {
	result := ""
	_, err := pool.Exec(ctx, UpdateUserUnBanDeluxe, profileId)
	if err != nil {
		result = err.Error()
		return false, result // false = operation failed
	}
	return true, result // true = operation succeeded
}

//err = pool.QueryRow(ctx, DoesUserDeluxeBan, user.ProfileId, ipAddress, time.Now()).Scan(&DeluxeBan, &BanLenght, &Publicreason)

func DoesUserDeluxeBanCheck(pool *pgxpool.Pool, ctx context.Context, profileID uint32, ipAddress string, csnum string) (bool, int64, string, error) {
	var err error
	DeluxeBan := false
	BanLenght := int64(0)
	Publicreason := ""

	if csnum != "" {
		err = pool.QueryRow(ctx, DoesUserDeluxeBanAndcsnum, profileID, ipAddress, time.Now(), csnum).Scan(&DeluxeBan, &BanLenght, &Publicreason)
	} else {
		err = pool.QueryRow(ctx, DoesUserDeluxeBan, profileID, ipAddress, time.Now()).Scan(&DeluxeBan, &BanLenght, &Publicreason)
	}

	if BanLenght < time.Now().Unix() {
		DeluxeBan = false
	}

	if err != nil {
		return DeluxeBan, BanLenght, Publicreason, err // Return false and the error
	}
	return DeluxeBan, BanLenght, Publicreason, nil // Return the trusted value and no error
}

// func DoesUserDeluxeBan(pool *pgxpool.Pool, ctx context.Context, profileID uint32, ipAddress string) (bool, error) {
// 	var trusted bool
// 	err := pool.QueryRow(ctx, DoesUserExistTrusted, profileID, ipAddress).Scan(&trusted)
// 	if err != nil {
// 		return false, err // Return false and the error
// 	}
// 	return trusted, nil // Return the trusted value and no error
// }

func Removevpnwhitelist(pool *pgxpool.Pool, ctx context.Context, profileId uint32) bool {
	_, err := pool.Exec(ctx, RemoveVPNWhitelist, profileId)
	return err == nil
}

func Resetcsnum(pool *pgxpool.Pool, ctx context.Context, profileId uint32) (bool, error) {
	csnum := ""
	if _, err := pool.Exec(ctx, Updateusercsnum, profileId, csnum); err != nil {
		return false, err
	}
	return true, nil
}

func Removecsnumwhitelistf(pool *pgxpool.Pool, ctx context.Context, profileId uint32) bool {
	_, err := pool.Exec(ctx, RemovecsnumWhitelist, profileId)
	return err == nil
}
func Addcsnumwhitelistf(pool *pgxpool.Pool, ctx context.Context, profileID uint32) (bool, error) {
	_, err := pool.Exec(ctx, AddcsnumWhitelist, profileID) //, userid, moderator)
	if err != nil {
		return false, err
	}
	return true, nil
}
func DoesUserVPNWhitelist(pool *pgxpool.Pool, ctx context.Context, profileID uint32) (bool, error) {
	var trusted bool
	err := pool.QueryRow(ctx, DoesUserExistVPNWhitelist, profileID).Scan(&trusted)
	if err != nil {
		return false, err // Return false and the error
	}
	return trusted, nil // Return the trusted value and no error
}
func DoesUsercsnumWhitelistDB(pool *pgxpool.Pool, ctx context.Context, profileID uint32) (bool, error) {
	var trusted bool
	err := pool.QueryRow(ctx, DoesUsercsnumWhitelist, profileID).Scan(&trusted)
	if err != nil {
		return false, err // Return false and the error
	}
	return trusted, nil // Return the trusted value and no error
}

var regexNumbers = regexp.MustCompile(`\d+`)

func getnum(number string) string {
	return strings.Join(regexNumbers.FindAllString(number, -1), "")
}

func Checkcsnum(pool *pgxpool.Pool, ctx context.Context, profileID uint32, csnum string) (bool, bool, error) {
	var csnumdb string
	whitelisted := false

	//csnum = "1" //test
	err := pool.QueryRow(ctx, Checkusercsnum, profileID).Scan(&csnumdb, &whitelisted)

	if err != nil {
		return false, whitelisted, err // Return false and the error
	}
	if csnumdb == "" {
		if _, err := pool.Exec(ctx, Updateusercsnum, profileID, csnum); err != nil {
			return false, whitelisted, err
		}
		csnumdb = csnum
	}

	if csnum != csnumdb {
		if getnum(csnum) != getnum(csnumdb) {
			logging.Notice("csnum does not match DB, DB: " + csnumdb + " csnum: " + csnum)
			return false, whitelisted, nil //incorrect csnum
		}
		logging.Notice("csnum does not match DB's Region, but allowing anyway, DB: " + csnumdb + " csnum: " + csnum)
	}

	return true, whitelisted, nil // Return if no issues and no error
}

func Checkcsnumban(pool *pgxpool.Pool, ctx context.Context, profileID uint32, csnum string) (bool, error) {

	return true, nil

}

func Addvpnwhitelist(pool *pgxpool.Pool, ctx context.Context, profileID uint32, userid int64, moderator int64) (bool, error) {
	_, err := pool.Exec(ctx, AddVPNWhitelist, profileID, userid, moderator)
	if err != nil {
		return false, err
	}
	return true, nil
}

func FetchVPNWhitelist(pool *pgxpool.Pool, ctx context.Context) ([]uint32, error) {
	var whitelistIDs []uint32

	rows, err := pool.Query(ctx, FetchVPNWhitelistList)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var profileID uint32
		if err := rows.Scan(&profileID); err != nil {
			return nil, err
		}
		whitelistIDs = append(whitelistIDs, profileID)
	}

	return whitelistIDs, nil
}

func FetchVPNWhitelistVerbose(pool *pgxpool.Pool, ctx context.Context) ([]struct {
	ProfileID     uint32
	LastIngameSN  string
	LastIPAddress string
}, error) {
	rows, err := pool.Query(ctx, FetchVPNWhitelistName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var data []struct {
		ProfileID     uint32
		LastIngameSN  string
		LastIPAddress string
	}

	for rows.Next() {
		var entry struct {
			ProfileID     uint32
			LastIngameSN  string
			LastIPAddress string
		}

		if err := rows.Scan(&entry.ProfileID, &entry.LastIngameSN, &entry.LastIPAddress); err != nil {
			return nil, err
		}

		data = append(data, entry)
	}

	return data, nil
}

func DoesUserTrusted(pool *pgxpool.Pool, ctx context.Context, profileID uint32) (bool, error) {
	var trusted bool
	err := pool.QueryRow(ctx, DoesUserExistTrusted, profileID).Scan(&trusted)
	if err != nil {
		return false, err // Return false and the error
	}
	return trusted, nil // Return the trusted value and no error
}

func AddTrusted(pool *pgxpool.Pool, ctx context.Context, profileID uint32) (bool, error) {
	_, err := pool.Exec(ctx, AddUserTrusted, profileID)
	if err != nil {
		return false, err
	}
	return true, nil
}

func FetchTrusted(pool *pgxpool.Pool, ctx context.Context) ([]uint32, error) {
	var trustedIDs []uint32

	rows, err := pool.Query(ctx, FetchTrustedList)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var profileID uint32
		if err := rows.Scan(&profileID); err != nil {
			// Log or print the error for debugging
			fmt.Println("Error scanning row:", err)
			return nil, err
		}
		trustedIDs = append(trustedIDs, profileID)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return trustedIDs, nil
}

func FetchUsernameAPI(pool *pgxpool.Pool, ctx context.Context, profileid uint32) (struct {
	ProfileID     uint32
	LastIngameSN  string
	LastIPAddress string
}, error) {
	var user struct {
		ProfileID     uint32
		LastIngameSN  string
		LastIPAddress string
	}

	err := pool.QueryRow(ctx, usernameapi, profileid).Scan(&user.ProfileID, &user.LastIngameSN, &user.LastIPAddress)
	if err != nil {
		return user, err // Return the empty struct and error
	}

	return user, nil
}

func FetchTrustedVerbose(pool *pgxpool.Pool, ctx context.Context) ([]struct {
	ProfileID     uint32
	LastIngameSN  string
	LastIPAddress string
}, error) {
	var trustedData []struct {
		ProfileID     uint32
		LastIngameSN  string
		LastIPAddress string
	}

	rows, err := pool.Query(ctx, FetchTrustedName) // Use the new query FetchTrustedName
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var profileID uint32
		var lastIngameSN, lastIPAddress string

		// Scan the row into variables
		if err := rows.Scan(&profileID, &lastIngameSN, &lastIPAddress); err != nil {
			// Log or print the error for debugging
			fmt.Println("Error scanning row:", err)
			return nil, err
		}

		// Append the results to the slice
		trustedData = append(trustedData, struct {
			ProfileID     uint32
			LastIngameSN  string
			LastIPAddress string
		}{
			ProfileID:     profileID,
			LastIngameSN:  lastIngameSN,
			LastIPAddress: lastIPAddress,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return trustedData, nil
}

func RemoveTrusted(pool *pgxpool.Pool, ctx context.Context, profileId uint32) bool {
	_, err := pool.Exec(ctx, RemoveUserTrusted, profileId)
	return err == nil
}

func UnbanUser(pool *pgxpool.Pool, ctx context.Context, profileId uint32) bool {
	_, err := pool.Exec(ctx, DisableUserBan, profileId)
	return err == nil
}

func GetMKWFriendInfo(pool *pgxpool.Pool, ctx context.Context, profileId uint32) string {
	var info string
	err := pool.QueryRow(ctx, GetMKWFriendInfoQuery, profileId).Scan(&info)
	if err != nil {
		return ""
	}

	return info
}

func UpdateMKWFriendInfo(pool *pgxpool.Pool, ctx context.Context, profileId uint32, info string) {
	_, err := pool.Exec(ctx, UpdateMKWFriendInfoQuery, profileId, info)
	if err != nil {
		panic(err)
	}
}
