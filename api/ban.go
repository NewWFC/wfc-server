package api

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
	"wwfc/common"
	"wwfc/database"
	"wwfc/gpcm"
	"wwfc/logging"
	"wwfc/qr2"

	"github.com/logrusorgru/aurora/v3"
)

func HandleBan(w http.ResponseWriter, r *http.Request) {
	var success bool
	var err string
	var statusCode int

	if r.Method == http.MethodPost {
		success, err, statusCode = handleBanImpl(r)
	} else if r.Method == http.MethodOptions {
		statusCode = http.StatusNoContent
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	} else {
		err = "Incorrect request. POST only."
		statusCode = http.StatusMethodNotAllowed
		w.Header().Set("Allow", "POST")
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")

	var jsonData []byte

	if statusCode != http.StatusNoContent {
		w.Header().Set("Content-Type", "application/json")

		if success {
			jsonData, _ = json.Marshal(map[string]string{"success": "true"})
		} else {
			jsonData, _ = json.Marshal(map[string]string{"error": err})
		}
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))

	w.WriteHeader(statusCode)
	w.Write(jsonData)
}

type BanRequestSpec struct {
	Secret       string `json:"secret"`
	ProfileID    uint32 `json:"pid"`
	Days         uint64 `json:"days"`
	Hours        uint64 `json:"hours"`
	Minutes      uint64 `json:"minutes"`
	Tos          bool   `json:"tos"`
	Reason       string `json:"reason"`
	ReasonHidden string `json:"reason_hidden"`
	Moderator    string `json:"moderator"`
}

func HandleUnBanDel(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	if err != nil {
		jsonData, _ := json.Marshal(map[string]string{"error": "Bad Request"})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
		w.Write(jsonData)
		return
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		jsonData, _ := json.Marshal(map[string]string{"error": "Bad Request"})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
		w.Write(jsonData)
		return
	}
	var plain bool
	plainbool := query.Get("plain")
	if plainbool != "" && plainbool == "true" {
		plain = true
	}

	message := handleUnBanImplDel(w, r)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")                                                                                      // HTTP/1.0 backward compatibility
	w.Header().Set("Expires", "0")                                                                                            // Ensure the response is treated as expired
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self';") //allow fetching in console

	if plain {
		if message == "" {
			message = "User unbanned"
		}
		//response = string(result)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(message)))
		w.Write([]byte(message))
	} else {
		if message != "" {
			jsonData, _ := json.Marshal(map[string]string{"error": message})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
			w.Write(jsonData)
		} else {
			jsonData, _ := json.Marshal(map[string]string{"success": "true"})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
			w.Write(jsonData)
		}
		// jsonResponse, err := json.Marshal(result)
		// w.Header().Set("Content-Type", "application/json")
		// // Set Content-Length header
		// w.Header().Set("Content-Length", strconv.Itoa(len(jsonResponse)))
		// if err != nil {
		// 	http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		// 	return
		// }
		// w.Write(jsonResponse)
	}

}

func handleUnBanImplDel(w http.ResponseWriter, r *http.Request) string { //unban
	// TODO: Actual authentication rather than a fixed secret
	// TODO: Use POST instead of GET

	u, err := url.Parse(r.URL.String())
	if err != nil {
		return "Bad request"
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "Bad request"
	}

	if query.Get("key") != apiSecret {
		if query.Get("key") != apiDeluxe {
			//*message += "Invalid API secret"
			return "Invalid API secret"
		}
	}

	// if apiSecret == "" || query.Get("secret") != apiSecret {
	// 	return "Invalid API secret"
	// }

	pidStr := query.Get("fc")
	if pidStr == "" {
		return "Missing fc in request"
	}

	// pid, err := strconv.ParseUint(pidStr, 10, 32)
	// if err != nil {
	// 	return "Invalid pid"
	// }

	fcStr := query.Get("fc")
	if fcStr == "" {
		//*message += "Missing Friend Code"
		return "missing FC"
	}
	re := regexp.MustCompile("[^0-9]")
	fcstrint := re.ReplaceAllString(fcStr, "")
	fc, err := strconv.ParseUint(fcstrint, 10, 64)
	if err != nil {
		//*message += "bad conversion from friend code"
		return "bad conversion"
	}
	var pidd uint64
	if len(fcstrint) < 13 {
		//need to convert to pid and reconvert to fc
		pidd = fc & 0xffffffff
		//gameId := "RMCJ"
		fc2str := common.CalcFriendCodeString(uint32(pidd), "RMCJ") //gameId)

		//fc2, err := strconv.ParseUint(fc2str, 10, 64)
		//if err != nil {
		//	return map[string]string{"error": "bad fc2 conversion to int, check in with marito man"}
		//}
		if fcStr != fc2str {
			//*message += "bad Friend Code, typo?"
			return "bad FC, typo?"
		} else {
			// _, err = database.AddTrusted(pool, ctx, uint32(pidd))
			// if err != nil {
			// 	//*message += "couldn't add user"
			// 	return "couldn't add user"
			// }
			// user, err := database.FetchUsernameAPI(pool, ctx, uint32(pidd))
			// if err != nil {
			// 	// The profile info was requested on is invalid.
			// 	//*message += "User Added."
			// 	return "User Added"
			// 	//g.replyError(ErrGetProfileBadProfile)

			// }
			// //*message += "User \"" + user.LastIngameSN + "\" Added."
			// jsonSafe, err := json.Marshal(user.LastIngameSN)
			// return "User Added " + "name: " + string(jsonSafe)

			//return map[string]string{"success": "test"}
		}

	} else {
		//*message += "Bad Friend Code size"
		return "bad size FC"
	}

	// tosStr := query.Get("tos")
	// if tosStr == "" {
	// 	return "Missing tos in request"
	// }

	// tos, err := strconv.ParseBool(tosStr)
	// if err != nil {
	// 	return "Invalid tos"
	// }

	// reason_hidden is optional

	banbool, result := database.UnBanUserDeluxe(pool, ctx, uint32(pidd))
	if !banbool {
		return "Failed to unban user, " + result
	}
	//result = result

	// if tos {
	// 	gpcm.KickPlayer(uint32(pid), "banned")
	// } else {
	// 	gpcm.KickPlayer(uint32(pid), "restricted")
	// }
	//gpcm.KickPlayer(uint32(pidd), "delbanned")

	return ""
}

func HandleBanDel(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	if err != nil {
		jsonData, _ := json.Marshal(map[string]string{"error": "Bad Request"})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
		w.Write(jsonData)
		return
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		jsonData, _ := json.Marshal(map[string]string{"error": "Bad Request"})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
		w.Write(jsonData)

		return
	}
	var plain bool
	plainbool := query.Get("plain")
	if plainbool != "" && plainbool == "true" {
		plain = true
	}

	message := handleBanImplDel(w, r)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")                                                                                      // HTTP/1.0 backward compatibility
	w.Header().Set("Expires", "0")                                                                                            // Ensure the response is treated as expired
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self';") //allow fetching in console

	if plain {
		if message == "" {
			message = "User banned" //no dot
		}
		//response = string(result)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(message)))
		w.Write([]byte(message))
	} else {
		if message != "" {
			jsonData, _ := json.Marshal(map[string]string{"error": message})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
			w.Write(jsonData)
		} else {
			jsonData, _ := json.Marshal(map[string]string{"success": "true"})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
			w.Write(jsonData)
		}
		// jsonResponse, err := json.Marshal(result)
		// w.Header().Set("Content-Type", "application/json")
		// // Set Content-Length header
		// w.Header().Set("Content-Length", strconv.Itoa(len(jsonResponse)))
		// if err != nil {
		// 	http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		// 	return
		// }
		// w.Write(jsonResponse)
	}

}

/*
func sendMessageToSession(msgType string, from uint32, session *GameSpySession, msg string) {
	message := common.CreateGameSpyMessage(common.GameSpyCommand{
		Command:      "bm",
		CommandValue: msgType,
		OtherValues: map[string]string{
			"f":   strconv.FormatUint(uint64(from), 10),
			"msg": msg,
		},
	})
	common.SendPacket(ServerName, session.ConnIndex, []byte(message))
}

func sendMessageToSessionBuffer(msgType string, from uint32, session *GameSpySession, msg string) {
	session.WriteBuffer += common.CreateGameSpyMessage(common.GameSpyCommand{
		Command:      "bm",
		CommandValue: msgType,
		OtherValues: map[string]string{
			"f":   strconv.FormatUint(uint64(from), 10),
			"msg": msg,
		},
	})
}

func sendMessageToProfileId(msgType string, from uint32, to uint32, msg string) bool {
	if session, ok := sessions[to]; ok && session.LoggedIn {
		sendMessageToSession(msgType, from, session, msg)
		return true
	}

	logging.Info("GPCM", "Destination", aurora.Cyan(to), "from", aurora.Cyan(from), "is not online")
	return false
}
*/

// func sendMessageToSession(msgType string, from uint32, session *GameSpySession, msg string) {
// 	message := common.CreateGameSpyMessage(common.GameSpyCommand{
// 		Command:      "bm",
// 		CommandValue: msgType,
// 		OtherValues: map[string]string{
// 			"f":   strconv.FormatUint(uint64(from), 10),
// 			"msg": msg,
// 		},
// 	})
// 	common.SendPacket(ServerName, session.ConnIndex, []byte(message))
// }

func handleBanImplDel(w http.ResponseWriter, r *http.Request) string {
	// TODO: Actual authentication rather than a fixed secret
	// TODO: Use POST instead of GET

	u, err := url.Parse(r.URL.String())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return "Bad request"
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return "Bad request"
	}

	if query.Get("key") != apiSecret {
		if query.Get("key") != apiDeluxe {
			//*message += "Invalid API secret"
			w.WriteHeader(http.StatusForbidden)
			return "Invalid API secret"
		}
	}

	// if apiSecret == "" || query.Get("secret") != apiSecret {
	// 	return "Invalid API secret"
	// }

	pidStr := query.Get("fc")
	if pidStr == "" {
		w.WriteHeader(http.StatusBadRequest)
		return "Missing fc in request"
	}

	// pid, err := strconv.ParseUint(pidStr, 10, 32)
	// if err != nil {
	// 	return "Invalid pid"
	// }

	fcStr := query.Get("fc")
	if fcStr == "" {
		//*message += "Missing Friend Code"
		w.WriteHeader(http.StatusBadRequest)
		return "missing FC"
	}
	re := regexp.MustCompile("[^0-9]")
	fcstrint := re.ReplaceAllString(fcStr, "")
	fc, err := strconv.ParseUint(fcstrint, 10, 64)
	if err != nil {
		//*message += "bad conversion from friend code"
		w.WriteHeader(http.StatusBadRequest)
		return "bad conversion"
	}
	var pidd uint64
	if len(fcstrint) < 13 {
		//need to convert to pid and reconvert to fc
		pidd = fc & 0xffffffff
		//gameId := "RMCJ"
		fc2str := common.CalcFriendCodeString(uint32(pidd), "RMCJ") //gameId)

		//fc2, err := strconv.ParseUint(fc2str, 10, 64)
		//if err != nil {
		//	return map[string]string{"error": "bad fc2 conversion to int, check in with marito man"}
		//}
		if fcStr != fc2str {
			//*message += "bad Friend Code, typo?"
			w.WriteHeader(http.StatusBadRequest)
			return "bad FC, typo?"
		} else {
			// _, err = database.AddTrusted(pool, ctx, uint32(pidd))
			// if err != nil {
			// 	//*message += "couldn't add user"
			// 	return "couldn't add user"
			// }
			// user, err := database.FetchUsernameAPI(pool, ctx, uint32(pidd))
			// if err != nil {
			// 	// The profile info was requested on is invalid.
			// 	//*message += "User Added."
			// 	return "User Added"
			// 	//g.replyError(ErrGetProfileBadProfile)

			// }
			// //*message += "User \"" + user.LastIngameSN + "\" Added."
			// jsonSafe, err := json.Marshal(user.LastIngameSN)
			// return "User Added " + "name: " + string(jsonSafe)

			//return map[string]string{"success": "test"}
		}

	} else {
		//*message += "Bad Friend Code size"
		w.WriteHeader(http.StatusBadRequest)
		return "bad size FC"
	}

	// tosStr := query.Get("tos")
	// if tosStr == "" {
	// 	return "Missing tos in request"
	// }

	// tos, err := strconv.ParseBool(tosStr)
	// if err != nil {
	// 	return "Invalid tos"
	// }

	minutes := uint64(0)
	if query.Get("minutes") != "" {
		minutesStr := query.Get("minutes")
		minutes, err = strconv.ParseUint(minutesStr, 10, 32)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return "Invalid minutes"
		}
	}

	hours := uint64(0)
	if query.Get("hours") != "" {
		hoursStr := query.Get("hours")
		hours, err = strconv.ParseUint(hoursStr, 10, 32)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return "Invalid hours"
		}
	}

	days := uint64(0)
	if query.Get("days") != "" {
		daysStr := query.Get("days")
		days, err = strconv.ParseUint(daysStr, 10, 32)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return "Invalid days"
		}
	}
	publicreason := query.Get("publicreason")
	reason := query.Get("reason")
	if "reason" == "" {
		w.WriteHeader(http.StatusBadRequest)
		return "Missing ban reason"
	}
	if len(publicreason) > 116 {
		w.WriteHeader(http.StatusBadRequest)
		return "public reason is too long, limit of 115 characters"
	}
	// if publicreason == "" {
	// 	publicreason = ""
	// }

	// reason_hidden is optional
	reasonHidden := query.Get("reason_hidden")

	moderator := query.Get("moderator")
	if "moderator" == "" {
		moderator = "admin"
	}

	minutes = days*24*60 + hours*60 + minutes
	if minutes == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return "Missing ban length"
	}

	length := time.Duration(minutes) * time.Minute

	banbool, result := database.BanUserDeluxe(pool, ctx, uint32(pidd), length, reason, reasonHidden, moderator, publicreason)
	if !banbool {
		w.WriteHeader(http.StatusInternalServerError)
		return "Failed to ban user, " + result
	}
	//result = result

	// if tos {
	// 	gpcm.KickPlayer(uint32(pid), "banned")
	// } else {
	// 	gpcm.KickPlayer(uint32(pid), "restricted")
	// }
	banuntil := time.Now().Add(length) //.Add(2 * time.Hour)
	go gpcm.KickCommand(uint32(pidd))
	//logging.Notice("Order test")
	//time.Sleep(time.Second * 1)
	go gpcm.KickPlayerDel(uint32(pidd), "delbanned", banuntil.Unix(), publicreason)

	return ""
}

func handleBanImpl(r *http.Request) (bool, string, int) {
	// TODO: Actual authentication rather than a fixed secret

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false, "Unable to read request body", http.StatusBadRequest
	}

	var req BanRequestSpec
	err = json.Unmarshal(body, &req)
	if err != nil {
		return false, err.Error(), http.StatusBadRequest
	}

	if apiSecret == "" || req.Secret != apiSecret {
		return false, "Invalid API secret in request", http.StatusUnauthorized
	}

	if req.ProfileID == 0 {
		return false, "Profile ID missing or 0 in request", http.StatusBadRequest
	}

	if req.Reason == "" {
		return false, "Missing ban reason in request", http.StatusBadRequest
	}

	moderator := req.Moderator
	if moderator == "" {
		moderator = "admin"
	}

	minutes := req.Days*24*60 + req.Hours*60 + req.Minutes
	if minutes == 0 {
		return false, "Ban length missing or 0", http.StatusBadRequest
	}

	length := time.Duration(minutes) * time.Minute

	logging.Notice("API:"+moderator, "Ban profile:", aurora.Cyan(req.ProfileID), "TOS:", aurora.Cyan(req.Tos), "Length:", aurora.Cyan(length), "Reason:", aurora.BrightCyan(req.Reason), "Reason (Hidden):", aurora.BrightCyan(req.ReasonHidden))

	if !database.BanUser(pool, ctx, req.ProfileID, req.Tos, length, req.Reason, req.ReasonHidden, moderator) {
		return false, "Failed to ban user", http.StatusInternalServerError
	}

	gpcm.KickPlayerCustomMessage(req.ProfileID, req.Reason, gpcm.WWFCMsgProfileRestrictedCustom)

	return true, "", http.StatusOK
}

func HandleFetch(w http.ResponseWriter, r *http.Request) {
	var plain bool
	//var err error
	//var jsonResponse []byte
	message := ""
	result := handleAddRemoveTrusted(w, r, &plain, &message)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")                                                                                      // HTTP/1.0 backward compatibility
	w.Header().Set("Expires", "0")                                                                                            // Ensure the response is treated as expired
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self';") //allow fetching in console

	if plain {
		//response = string(result)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(message)))
		w.Write([]byte(message))
	} else {
		jsonResponse, err := json.Marshal(result)
		w.Header().Set("Content-Type", "application/json")
		// Set Content-Length header
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonResponse)))
		if err != nil {
			http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
			return
		}
		w.Write(jsonResponse)
	}

}

func handleAddRemoveTrusted(w http.ResponseWriter, r *http.Request, plain *bool, message *string) interface{} {
	// TODO: Actual authentication rather than a fixed secret
	// TODO: Use POST instead of GET
	var trusted bool
	var pid32 uint32
	u, err := url.Parse(r.URL.String())
	if err != nil {
		//*message += "Bad request"
		return map[string]string{"error": "Bad request"}
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		//*message += "Bad request"
		return map[string]string{"error": "Bad request"}
	}

	plainbool := query.Get("plain")
	if plainbool != "" && plainbool == "true" {
		*plain = true
	}
	if query.Get("key") != apiSecret {
		if query.Get("key") != apiTrusted {
			*message += "Invalid API secret"
			return map[string]string{"error": "Invalid API secret"}
		}
	}
	if apiSecret == "" || apiTrusted == "" {
		*message += "Woops, haven't set up config"
		return map[string]string{"error": "Woops, haven't set up config"}

	}

	request := query.Get("type")
	if "type" == "" {
		*message += "Missing Add, Add2, Remove, Remove2 from type"
		return map[string]string{"error": "Missing Add or Remove or FETCH"}
	}
	var pid2 uint32
	if request != "FETCH" && request != "FETCH2" {
		if request == "Add2" || request == "Remove2" {
			fcStr := query.Get("fc")
			if fcStr == "" {
				*message += "Missing Friend Code"
				return map[string]string{"error": "missing FC"}
			}
			re := regexp.MustCompile("[^0-9]")
			fcstrint := re.ReplaceAllString(fcStr, "")
			fc, err := strconv.ParseUint(fcstrint, 10, 64)
			if err != nil {
				*message += "bad Friend Code conversion"
				return map[string]string{"error": "bad conversion"}
			}
			pid := fc & 0xffffffff
			pid32 = uint32(pid)
			pid2 = pid32
			trusted, err = database.DoesUserTrusted(pool, ctx, pid32)
			if err != nil {
				*message += "An error occured checking database"
				return map[string]string{"error": "An error occured"}
				//return "An error occured"
			}

		} else {
			pidStr := query.Get("pid")
			if pidStr == "" {
				*message += "Missing pid in request"
				return map[string]string{"error": "Missing pid in request"}
			}

			pid, err := strconv.ParseUint(pidStr, 10, 32)
			if err != nil {
				*message += "Invalid PID"
				return map[string]string{"error": "Invalid pid"}
			}

			pid32 = uint32(pid)

			trusted, err = database.DoesUserTrusted(pool, ctx, pid32)
			if err != nil {
				*message += "An error occured checking database"
				return "An error occured checking database"
			}
		}

	}

	switch request {
	case "FETCH":
		trustedIDs, err := database.FetchTrusted(pool, ctx)
		if err != nil {
			return map[string]string{"error": "Error fetching trusted IDs"}
		}

		// Create a map to store friend codes
		friendCodes := make(map[uint32]string)

		// Iterate through trustedIDs and calculate friend codes
		for _, pid := range trustedIDs {
			fc := common.CalcFriendCodeString(pid, "RMCJ") // Assuming "RMCJ" is the gameId
			friendCodes[pid] = fc
		}

		// Convert the map to JSON
		friendCodesJSON, err := json.Marshal(friendCodes)
		if err != nil {
			return map[string]string{"error": "Error converting friend codes to JSON"}
		}

		return string(friendCodesJSON)
	case "FETCH2":
		trustedData, err := database.FetchTrustedVerbose(pool, ctx)
		if err != nil {
			return map[string]string{"error": "Error fetching trusted data"}
		}

		// Create a map to store the results
		result := make(map[string]map[string]string)

		// Iterate through the verbose data and process each record
		for _, data := range trustedData {
			fc := common.CalcFriendCodeString(data.ProfileID, "RMCJ") // Assuming "RMCJ" is the gameId

			// Store friend code, last_ingamesn, and last_ip_address in the map
			result[fmt.Sprint(data.ProfileID)] = map[string]string{
				//"profile_id":      fmt.Sprint(data.ProfileID), // Convert uint32 to string
				"fc":              (fc),
				"last_ingamesn":   html.EscapeString(data.LastIngameSN),
				"last_ip_address": html.EscapeString(data.LastIPAddress),
			}
		}

		// Convert the result map to JSON
		resultJSON, err := json.Marshal(result)
		if err != nil {
			return map[string]string{"error": "Error converting result to JSON"}
		}

		return string(resultJSON)

	case "Add2":
		if !trusted {
			fcStr := query.Get("fc")
			if fcStr == "" {
				*message += "Missing Friend Code"
				return map[string]string{"error": "missing FC"}
			}
			re := regexp.MustCompile("[^0-9]")
			fcstrint := re.ReplaceAllString(fcStr, "")
			fc, err := strconv.ParseUint(fcstrint, 10, 64)
			if err != nil {
				*message += "bad conversion from friend code"
				return map[string]string{"error": "bad conversion"}
			}
			if len(fcstrint) < 13 {
				//need to convert to pid and reconvert to fc
				pidd := fc & 0xffffffff
				//gameId := "RMCJ"
				fc2str := common.CalcFriendCodeString(uint32(pidd), "RMCJ") //gameId)

				//fc2, err := strconv.ParseUint(fc2str, 10, 64)
				//if err != nil {
				//	return map[string]string{"error": "bad fc2 conversion to int, check in with marito man"}
				//}
				if fcStr != fc2str {
					*message += "bad Friend Code, typo?"
					return map[string]string{"error": "bad FC, typo?"}
				} else {
					_, err = database.AddTrusted(pool, ctx, uint32(pidd))
					if err != nil {
						*message += "couldn't add user"
						return map[string]string{"error": "couldn't add user"}
					}
					user, err := database.FetchUsernameAPI(pool, ctx, uint32(pidd))
					if err != nil {
						// The profile info was requested on is invalid.
						*message += "User Added."
						return map[string]string{"success": "User Added"}
						//g.replyError(ErrGetProfileBadProfile)

					}
					*message += "User \"" + user.LastIngameSN + "\" Added."
					jsonSafe, err := json.Marshal(user.LastIngameSN)
					return map[string]string{"success": "User Added", "name": string(jsonSafe)}

					//return map[string]string{"success": "test"}
				}

			} else {
				*message += "Bad Friend Code size"
				return map[string]string{"error": "bad size FC"}
			}
		}

		if trusted {
			user, err := database.FetchUsernameAPI(pool, ctx, uint32(pid2))
			if err != nil {
				*message += "User is already verified."
				return map[string]string{"error": "Error, user is already whitelisted"}
			}
			*message += "User \"" + user.LastIngameSN + "\" is already verified."
			return map[string]string{"error": "Error, user is already whitelisted"}
		}
		*message += "Error while checking boolean (add)"
		return map[string]string{"error": "Error while checking boolean (add)"}

		// if !trusted {
		// 	_, err = database.AddTrusted(pool, ctx, pid32)
		// 	if err != nil {
		// 		return map[string]string{"error": "couldn't add user"}
		// 	}
		// 	return map[string]string{"success": "User Added"}
		// }
		// if trusted {
		// 	return map[string]string{"error": "Error, user is already whitelisted"}
		// }

		// return map[string]string{"error": "Error while checking boolean (add)"}

	case "Add":
		if !trusted {
			_, err = database.AddTrusted(pool, ctx, pid32)
			if err != nil {
				*message += "couldn't add user"
				return map[string]string{"error": "couldn't add user"}
			}
			*message += "User Added"
			return map[string]string{"success": "User Added"}
		}
		if trusted {
			*message += "Error, user is already whitelisted"
			return map[string]string{"error": "Error, user is already whitelisted"}
		}
		*message += "Error while checking boolean (add)"
		return map[string]string{"error": "Error while checking boolean (add)"}

	case "Remove2":
		if trusted {
			fcStr := query.Get("fc")
			if fcStr == "" {
				*message += "Friend Code missing"
				return map[string]string{"error": "missing FC"}
			}
			re := regexp.MustCompile("[^0-9]")
			fcstrint := re.ReplaceAllString(fcStr, "")
			fc, err := strconv.ParseUint(fcstrint, 10, 64)
			if err != nil {
				*message += "invalid conversion from Friend Code input"
				return map[string]string{"error": "bad conversion"}
			}
			if len(fcstrint) < 13 {
				//need to convert to pid and reconvert to fc
				pidd := fc & 0xffffffff
				//gameId := "RMCJ"
				fc2str := common.CalcFriendCodeString(uint32(pidd), "RMCJ") //gameId)

				//fc2, err := strconv.ParseUint(fc2str, 10, 64)
				//if err != nil {
				//	return map[string]string{"error": "bad fc2 conversion to int, check in with marito man"}
				//}
				if fcStr != fc2str {
					*message += "Friend Code does match the format of \"Mario Kart Wii\""
					return map[string]string{"error": "bad FC, typo?"}
				} else {
					database.RemoveTrusted(pool, ctx, uint32(pidd))
					user, err := database.FetchUsernameAPI(pool, ctx, uint32(pidd))
					if err != nil {
						*message += "User Removed."
						return map[string]string{"success": "User Removed"}
					}

					*message += "User \"" + user.LastIngameSN + "\" Removed."
					jsonSafe, err := json.Marshal(user.LastIngameSN)
					if err != nil {
						return map[string]string{"success": "User Removed", "name": "bad name"}
					}
					return map[string]string{"success": "User Removed", "name": string(jsonSafe)}
					//return map[string]string{"success": "test"}
				}

			} else {
				*message += "Incorrect Friend Code Format"
				return map[string]string{"error": "bad size FC"}
			}
		}

		if !trusted {
			*message += "User isn't whitelisted, cannot remove."
			return map[string]string{"error": "User isn't whitelisted, cannot remove"}
		}
		*message += "Error while checking boolean, coding error?"
		return map[string]string{"error": "Error while checking boolean (remove)"}

	case "Remove":
		if trusted {
			database.RemoveTrusted(pool, ctx, pid32)
			*message += "User Removed"
			return map[string]string{"success": "User Removed"}
		}

		if !trusted {
			*message += "User isn't whitelisted, cannot remove"
			return map[string]string{"error": "User isn't whitelisted, cannot remove"}
		}
		*message += "Error while checking boolean (remove)"
		return map[string]string{"error": "Error while checking boolean (remove)"}

	default:
		*message += "missing Add, Add2, Remove, Remove2 from type"
		return map[string]string{"error": "missing Add or Remove or FETCH"}
	}
}

func HandleTest(w http.ResponseWriter, r *http.Request) {
	var plain bool
	//var err error
	//var jsonResponse []byte
	message := ""
	result := handlePayload(w, r, &plain, &message)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")                                                                                      // HTTP/1.0 backward compatibility
	w.Header().Set("Expires", "0")                                                                                            // Ensure the response is treated as expired
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self';") //allow fetching in console

	if plain {
		//response = string(result)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(message)))
		w.Write([]byte(message))
	} else {
		jsonResponse, err := json.Marshal(result)
		w.Header().Set("Content-Type", "application/json")
		// Set Content-Length header
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonResponse)))
		if err != nil {
			http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
			return
		}
		w.Write(jsonResponse)
	}

}

func handlePayload(w http.ResponseWriter, r *http.Request, plain *bool, message *string) interface{} {
	// TODO: Actual authentication rather than a fixed secret
	// TODO: Use POST instead of GET
	//var trusted bool
	//var pid32 uint32
	u, err := url.Parse(r.URL.String())
	if err != nil {
		//*message += "Bad request"
		return map[string]string{"error": "Bad request"}
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		//*message += "Bad request"
		return map[string]string{"error": "Bad request"}
	}

	plainbool := query.Get("plain")
	if plainbool != "" && plainbool == "true" {
		*plain = true
	}
	if query.Get("secret") != apiSecret {
		if query.Get("secret") != apiTrusted {
			*message += "Invalid API secret"
			return map[string]string{"error": "Invalid API secret"}
		}
	}
	if apiSecret == "" || apiTrusted == "" {
		*message += "Woops, haven't set up config"
		return map[string]string{"error": "Woops, haven't set up config"}

	}

	request := query.Get("type")
	if "type" == "" {
		*message += "Missing Add, Add2, Remove, Remove2 from type"
		return map[string]string{"error": "Missing Add or Remove or FETCH"}
	}

	pidStr := query.Get("pid")
	if pidStr == "" {
		*message += "Missing pid in request"
		return map[string]string{"error": "Missing pid in request"}
	}

	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		*message += "Invalid PID"
		return map[string]string{"error": "Invalid pid"}
	}

	switch request {
	case "payload":

		ok := gpcm.PayloadUser(uint32(pid))
		if !ok {
			*message += "Not Done"
			return map[string]string{"error": "Not Done"}

		}
		ok = qr2.PayloadUser(uint32(pid))

		if !ok {
			*message += "Semi Done"
			return map[string]string{"error": "Semi Done"}
		}

		return map[string]string{"success": "Done"}
		//g.NeedsExploit = true
		//deviceAuth = false
	case "dc":
		go gpcm.KickCommand(uint32(pid))
		*message += "Done"
		return map[string]string{"success": "Done"}
	default:
		*message += "nothing"
		return map[string]string{"nothing": "nothing"}

	}

}

func HandleVPNFetch(w http.ResponseWriter, r *http.Request) {
	var plain bool
	//var err error
	//var jsonResponse []byte
	message := ""
	result := handleAddRemoveVPNWhitelist(w, r, &plain, &message)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")                                                                                      // HTTP/1.0 backward compatibility
	w.Header().Set("Expires", "0")                                                                                            // Ensure the response is treated as expired
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self';") //allow fetching in console

	if plain {
		//response = string(result)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(message)))
		w.Write([]byte(message))
	} else {
		jsonResponse, err := json.Marshal(result)
		w.Header().Set("Content-Type", "application/json")
		// Set Content-Length header
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonResponse)))
		if err != nil {
			http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
			return
		}
		w.Write(jsonResponse)
	}

}

func handleAddRemoveVPNWhitelist(w http.ResponseWriter, r *http.Request, plain *bool, message *string) interface{} {
	// TODO: Actual authentication rather than a fixed secret
	// TODO: Use POST instead of GET
	var whitelisted bool
	var pid32 uint32
	u, err := url.Parse(r.URL.String())
	if err != nil {
		return map[string]string{"error": "Bad request"}
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return map[string]string{"error": "Bad request"}
	}

	plainbool := query.Get("plain")
	if plainbool != "" && plainbool == "true" {
		*plain = true
	}
	if query.Get("key") != apiSecret {
		if query.Get("key") != apiTrusted {
			*message += "Invalid API secret"
			return map[string]string{"error": "Invalid API secret"}
		}
	}
	if apiSecret == "" || apiTrusted == "" {
		*message += "Woops, haven't set up config"
		return map[string]string{"error": "Woops, haven't set up config"}

	}

	getAuditFields := func() (int64, int64, bool) {
		userIDStr := query.Get("userid")
		if userIDStr == "" {
			*message += "Missing userid "
			return 0, 0, false
		}
		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			*message += "Invalid userid "
			return 0, 0, false
		}

		moderatorStr := query.Get("moderator")
		if moderatorStr == "" {
			*message += "Missing moderator "
			return 0, 0, false
		}
		moderatorID, err := strconv.ParseInt(moderatorStr, 10, 64)
		if err != nil {
			*message += "Invalid moderator "
			return 0, 0, false
		}

		return userID, moderatorID, true
	}

	request := query.Get("type")
	if "type" == "" {
		*message += "Missing Add or Remove from type"
		return map[string]string{"error": "Missing Add or Remove or FETCH"}
	}
	var pid2 uint32
	if request != "FETCH" && request != "FETCH2" {
		if request == "Add" || request == "Remove" {
			fcStr := query.Get("fc")
			if fcStr == "" {
				*message += "Missing Friend Code"
				return map[string]string{"error": "missing FC"}
			}
			re := regexp.MustCompile("[^0-9]")
			fcstrint := re.ReplaceAllString(fcStr, "")
			fc, err := strconv.ParseUint(fcstrint, 10, 64)
			if err != nil {
				*message += "bad Friend Code conversion"
				return map[string]string{"error": "bad conversion"}
			}
			pid := fc & 0xffffffff
			pid32 = uint32(pid)
			pid2 = pid32
			whitelisted, err = database.DoesUserVPNWhitelist(pool, ctx, pid32)
			if err != nil {
				*message += "An error occured checking database"
				return map[string]string{"error": "An error occured"}
			}

		} else {
			pidStr := query.Get("pid")
			if pidStr == "" {
				*message += "Missing pid in request"
				return map[string]string{"error": "Missing pid in request"}
			}

			pid, err := strconv.ParseUint(pidStr, 10, 32)
			if err != nil {
				*message += "Invalid PID"
				return map[string]string{"error": "Invalid pid"}
			}

			pid32 = uint32(pid)

			whitelisted, err = database.DoesUserVPNWhitelist(pool, ctx, pid32)
			if err != nil {
				*message += "An error occured checking database"
				return map[string]string{"error": "An error occured"}
			}
		}

	}

	switch request {
	case "FETCH":
		whitelistIDs, err := database.FetchVPNWhitelist(pool, ctx)
		if err != nil {
			return map[string]string{"error": "Error fetching VPN whitelist IDs"}
		}

		friendCodes := make(map[uint32]string)
		for _, pid := range whitelistIDs {
			fc := common.CalcFriendCodeString(pid, "RMCJ")
			friendCodes[pid] = fc
		}

		friendCodesJSON, err := json.Marshal(friendCodes)
		if err != nil {
			return map[string]string{"error": "Error converting friend codes to JSON"}
		}

		return string(friendCodesJSON)
	case "FETCH2":
		whitelistData, err := database.FetchVPNWhitelistVerbose(pool, ctx)
		if err != nil {
			return map[string]string{"error": "Error fetching VPN whitelist data"}
		}

		result := make(map[string]map[string]string)
		for _, data := range whitelistData {
			fc := common.CalcFriendCodeString(data.ProfileID, "RMCJ")
			result[fmt.Sprint(data.ProfileID)] = map[string]string{
				"fc":              fc,
				"last_ingamesn":   html.EscapeString(data.LastIngameSN),
				"last_ip_address": html.EscapeString(data.LastIPAddress),
			}
		}

		resultJSON, err := json.Marshal(result)
		if err != nil {
			return map[string]string{"error": "Error converting result to JSON"}
		}

		return string(resultJSON)

	case "Add":
		if !whitelisted {
			fcStr := query.Get("fc")
			if fcStr == "" {
				*message += "Missing Friend Code"
				return map[string]string{"error": "missing FC"}
			}
			re := regexp.MustCompile("[^0-9]")
			fcstrint := re.ReplaceAllString(fcStr, "")
			fc, err := strconv.ParseUint(fcstrint, 10, 64)
			if err != nil {
				*message += "bad conversion from friend code"
				return map[string]string{"error": "bad conversion"}
			}
			if len(fcstrint) < 13 {
				pidd := fc & 0xffffffff
				fc2str := common.CalcFriendCodeString(uint32(pidd), "RMCJ")
				if fcStr != fc2str {
					*message += "bad Friend Code, typo?"
					return map[string]string{"error": "bad FC, typo?"}
				}

				userID, moderatorID, ok := getAuditFields()
				if !ok {
					return map[string]string{"error": "Missing userid or moderator"}
				}

				if _, err = database.Addvpnwhitelist(pool, ctx, uint32(pidd), userID, moderatorID); err != nil {
					*message += "couldn't add user"
					return map[string]string{"error": "couldn't add user"}
				}
				user, err := database.FetchUsernameAPI(pool, ctx, uint32(pidd))
				if err != nil {
					*message += "User Added."
					return map[string]string{"success": "User Added"}
				}
				*message += "User \"" + user.LastIngameSN + "\" Added to VPN whitelist."
				jsonSafe, err := json.Marshal(user.LastIngameSN)
				return map[string]string{"success": "User Added", "name": string(jsonSafe)}
			}
			*message += "Bad Friend Code size"
			return map[string]string{"error": "bad size FC"}
		}

		if whitelisted {
			user, err := database.FetchUsernameAPI(pool, ctx, uint32(pid2))
			if err != nil {
				*message += "User is already on VPN whitelist."
				return map[string]string{"error": "Error, user is already whitelisted"}
			}
			*message += "User \"" + user.LastIngameSN + "\" is already on VPN whitelist."
			return map[string]string{"error": "Error, user is already whitelisted"}
		}
		*message += "Error while checking boolean (add)"
		return map[string]string{"error": "Error while checking boolean (add)"}

		// case "Add":
		// 	if !whitelisted {
		// 		userID, moderatorID, ok := getAuditFields()
		// 		if !ok {
		// 			return map[string]string{"error": "Missing userid or moderator"}
		// 		}
		// 		if _, err = database.Addvpnwhitelist(pool, ctx, pid32, userID, moderatorID); err != nil {
		// 			*message += "couldn't add user"
		// 			return map[string]string{"error": "couldn't add user"}
		// 		}
		// 		*message += "User Added to VPN whitelist"
		// 		return map[string]string{"success": "User Added"}
		// 	}
		// 	if whitelisted {
		// 		*message += "Error, user is already on VPN whitelist"
		// 		return map[string]string{"error": "Error, user is already whitelisted"}
		// 	}
		// 	*message += "Error while checking boolean (add)"
		// 	return map[string]string{"error": "Error while checking boolean (add)"}

	case "Remove":
		if whitelisted {
			fcStr := query.Get("fc")
			if fcStr == "" {
				*message += "Friend Code missing"
				return map[string]string{"error": "missing FC"}
			}
			re := regexp.MustCompile("[^0-9]")
			fcstrint := re.ReplaceAllString(fcStr, "")
			fc, err := strconv.ParseUint(fcstrint, 10, 64)
			if err != nil {
				*message += "invalid conversion from Friend Code input"
				return map[string]string{"error": "bad conversion"}
			}
			if len(fcstrint) < 13 {
				pidd := fc & 0xffffffff
				fc2str := common.CalcFriendCodeString(uint32(pidd), "RMCJ")
				if fcStr != fc2str {
					*message += "Friend Code does match the format of \"Mario Kart Wii\""
					return map[string]string{"error": "bad FC, typo?"}
				}

				database.Removevpnwhitelist(pool, ctx, uint32(pidd))
				user, err := database.FetchUsernameAPI(pool, ctx, uint32(pidd))
				if err != nil {
					*message += "User Removed."
					return map[string]string{"success": "User Removed"}
				}

				*message += "User \"" + user.LastIngameSN + "\" Removed from VPN whitelist."
				jsonSafe, err := json.Marshal(user.LastIngameSN)
				if err != nil {
					return map[string]string{"success": "User Removed", "name": "bad name"}
				}
				return map[string]string{"success": "User Removed", "name": string(jsonSafe)}
			}
			*message += "Incorrect Friend Code Format"
			return map[string]string{"error": "bad size FC"}
		}

		if !whitelisted {
			*message += "User isn't on VPN whitelist, cannot remove."
			return map[string]string{"error": "User isn't whitelisted, cannot remove"}
		}
		*message += "Error while checking boolean, coding error?"
		return map[string]string{"error": "Error while checking boolean (remove)"}

		// case "Remove":
		// 	if whitelisted {
		// 		database.Removevpnwhitelist(pool, ctx, pid32)
		// 		*message += "User Removed from VPN whitelist"
		// 		return map[string]string{"success": "User Removed"}
		// 	}
		//
		// 	if !whitelisted {
		// 		*message += "User isn't on VPN whitelist, cannot remove"
		// 		return map[string]string{"error": "User isn't whitelisted, cannot remove"}
		// 	}
		// 	*message += "Error while checking boolean (remove)"
		// 	return map[string]string{"error": "Error while checking boolean (remove)"}

	default:
		*message += "missing Add, Add2, Remove, Remove2 from type"
		return map[string]string{"error": "missing Add or Remove or FETCH"}
	}
}

func HandlecsnumFetch(w http.ResponseWriter, r *http.Request) {
	var plain bool
	//var err error
	//var jsonResponse []byte
	message := ""
	result := handleAddRemoveCSNUM(w, r, &plain, &message)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")                                                                                      // HTTP/1.0 backward compatibility
	w.Header().Set("Expires", "0")                                                                                            // Ensure the response is treated as expired
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self';") //allow fetching in console

	if plain {
		//response = string(result)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(message)))
		w.Write([]byte(message))
	} else {
		jsonResponse, err := json.Marshal(result)
		w.Header().Set("Content-Type", "application/json")
		// Set Content-Length header
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonResponse)))
		if err != nil {
			http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
			return
		}
		w.Write(jsonResponse)
	}

}

func handleAddRemoveCSNUM(w http.ResponseWriter, r *http.Request, plain *bool, message *string) interface{} {
	// TODO: Actual authentication rather than a fixed secret
	// TODO: Use POST instead of GET
	var whitelisted bool
	var pid32 uint32
	u, err := url.Parse(r.URL.String())
	if err != nil {
		return map[string]string{"error": "Bad request"}
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return map[string]string{"error": "Bad request"}
	}

	plainbool := query.Get("plain")
	if plainbool != "" && plainbool == "true" {
		*plain = true
	}
	if query.Get("key") != apiSecret {
		if query.Get("key") != apiTrusted {
			*message += "Invalid API secret"
			return map[string]string{"error": "Invalid API secret"}
		}
	}
	if apiSecret == "" || apiTrusted == "" {
		*message += "Woops, haven't set up config"
		return map[string]string{"error": "Woops, haven't set up config"}

	}

	// getAuditFields := func() (int64, int64, bool) {
	// 	userIDStr := query.Get("userid")
	// 	if userIDStr == "" {
	// 		*message += "Missing userid "
	// 		return 0, 0, false
	// 	}
	// 	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	// 	if err != nil {
	// 		*message += "Invalid userid "
	// 		return 0, 0, false
	// 	}

	// 	moderatorStr := query.Get("moderator")
	// 	if moderatorStr == "" {
	// 		*message += "Missing moderator "
	// 		return 0, 0, false
	// 	}
	// 	moderatorID, err := strconv.ParseInt(moderatorStr, 10, 64)
	// 	if err != nil {
	// 		*message += "Invalid moderator "
	// 		return 0, 0, false
	// 	}

	// 	return userID, moderatorID, true
	// }

	request := query.Get("type")
	if "type" == "" {
		*message += "Missing Add or Remove from type"
		return map[string]string{"error": "Missing Add or Remove or FETCH"}
	}
	var pid2 uint32
	//if request != "FETCH" && request != "FETCH2" {
	if request == "Add" || request == "Remove" {
		fcStr := query.Get("fc")
		if fcStr == "" {
			*message += "Missing Friend Code"
			return map[string]string{"error": "missing FC"}
		}
		re := regexp.MustCompile("[^0-9]")
		fcstrint := re.ReplaceAllString(fcStr, "")
		fc, err := strconv.ParseUint(fcstrint, 10, 64)
		if err != nil {
			*message += "bad Friend Code conversion"
			return map[string]string{"error": "bad conversion"}
		}
		pid := fc & 0xffffffff
		pid32 = uint32(pid)
		pid2 = pid32
		whitelisted, err = database.DoesUsercsnumWhitelistDB(pool, ctx, pid32)
		if err != nil {
			*message += "An error occured checking database"
			return map[string]string{"error": "An error occured"}
		}

		// } else {
		// 	pidStr := query.Get("pid")
		// 	if pidStr == "" {
		// 		*message += "Missing pid in request"
		// 		return map[string]string{"error": "Missing pid in request"}
		// 	}

		// 	pid, err := strconv.ParseUint(pidStr, 10, 32)
		// 	if err != nil {
		// 		*message += "Invalid PID"
		// 		return map[string]string{"error": "Invalid pid"}
		// 	}

		// 	pid32 = uint32(pid)

		// 	whitelisted, err = database.DoesUsercsnumWhitelistDB(pool, ctx, pid32)
		// 	if err != nil {
		// 		*message += "An error occured checking database"
		// 		return map[string]string{"error": "An error occured"}
		// 	}
		// }

	}

	switch request {
	case "Reset":
		//if whitelisted {
		fcStr := query.Get("fc")
		if fcStr == "" {
			*message += "Friend Code missing"
			return map[string]string{"error": "missing FC"}
		}
		re := regexp.MustCompile("[^0-9]")
		fcstrint := re.ReplaceAllString(fcStr, "")
		fc, err := strconv.ParseUint(fcstrint, 10, 64)
		if err != nil {
			*message += "invalid conversion from Friend Code input"
			return map[string]string{"error": "bad conversion"}
		}
		if len(fcstrint) < 13 {
			pidd := fc & 0xffffffff
			fc2str := common.CalcFriendCodeString(uint32(pidd), "RMCJ")
			if fcStr != fc2str {
				*message += "Friend Code does match the format of \"Mario Kart Wii\""
				return map[string]string{"error": "bad FC, typo?"}
			}

			ok, err := database.Resetcsnum(pool, ctx, uint32(pidd))
			if !ok {
				*message += "Error reseting csnum."
				return map[string]string{"success": "Error reseting csnum"}
			}
			user, err := database.FetchUsernameAPI(pool, ctx, uint32(pidd))
			if err != nil {
				*message += "User csnum reset."
				return map[string]string{"success": "User csnum reset"}
			}

			*message += "User \"" + user.LastIngameSN + "\" csnum reseted."
			jsonSafe, err := json.Marshal(user.LastIngameSN)
			if err != nil {
				return map[string]string{"success": "User Removed", "name": "bad name"}
			}
			return map[string]string{"success": "User Removed", "name": string(jsonSafe)}
		}
		*message += "Incorrect Friend Code Format"
		return map[string]string{"error": "bad size FC"}
		//}

		// if !whitelisted {
		// 	*message += "User isn't on VPN whitelist, cannot remove."
		// 	return map[string]string{"error": "User isn't whitelisted, cannot remove"}
		// }
		*message += "Error while checking boolean, coding error?"
		return map[string]string{"error": "Error while checking boolean (remove)"}

	// case "FETCH":
	// 	whitelistIDs, err := database.FetchVPNWhitelist(pool, ctx)
	// 	if err != nil {
	// 		return map[string]string{"error": "Error fetching VPN whitelist IDs"}
	// 	}

	// 	friendCodes := make(map[uint32]string)
	// 	for _, pid := range whitelistIDs {
	// 		fc := common.CalcFriendCodeString(pid, "RMCJ")
	// 		friendCodes[pid] = fc
	// 	}

	// 	friendCodesJSON, err := json.Marshal(friendCodes)
	// 	if err != nil {
	// 		return map[string]string{"error": "Error converting friend codes to JSON"}
	// 	}

	// 	return string(friendCodesJSON)
	// case "FETCH2":
	// 	whitelistData, err := database.FetchVPNWhitelistVerbose(pool, ctx)
	// 	if err != nil {
	// 		return map[string]string{"error": "Error fetching VPN whitelist data"}
	// 	}

	// 	result := make(map[string]map[string]string)
	// 	for _, data := range whitelistData {
	// 		fc := common.CalcFriendCodeString(data.ProfileID, "RMCJ")
	// 		result[fmt.Sprint(data.ProfileID)] = map[string]string{
	// 			"fc":              fc,
	// 			"last_ingamesn":   html.EscapeString(data.LastIngameSN),
	// 			"last_ip_address": html.EscapeString(data.LastIPAddress),
	// 		}
	// 	}

	// 	resultJSON, err := json.Marshal(result)
	// 	if err != nil {
	// 		return map[string]string{"error": "Error converting result to JSON"}
	// 	}

	// 	return string(resultJSON)

	case "Add":
		if !whitelisted {
			fcStr := query.Get("fc")
			if fcStr == "" {
				*message += "Missing Friend Code"
				return map[string]string{"error": "missing FC"}
			}
			re := regexp.MustCompile("[^0-9]")
			fcstrint := re.ReplaceAllString(fcStr, "")
			fc, err := strconv.ParseUint(fcstrint, 10, 64)
			if err != nil {
				*message += "bad conversion from friend code"
				return map[string]string{"error": "bad conversion"}
			}
			if len(fcstrint) < 13 {
				pidd := fc & 0xffffffff
				fc2str := common.CalcFriendCodeString(uint32(pidd), "RMCJ")
				if fcStr != fc2str {
					*message += "bad Friend Code, typo?"
					return map[string]string{"error": "bad FC, typo?"}
				}

				//userID, moderatorID, ok := getAuditFields()
				// if !ok {
				// 	return map[string]string{"error": "Missing userid or moderator"}
				// }

				if _, err = database.Addcsnumwhitelistf(pool, ctx, uint32(pidd)); err != nil {
					*message += "couldn't add user"
					return map[string]string{"error": "couldn't add user"}
				}
				user, err := database.FetchUsernameAPI(pool, ctx, uint32(pidd))
				if err != nil {
					*message += "User Added."
					return map[string]string{"success": "User Added"}
				}
				*message += "User \"" + user.LastIngameSN + "\" Added to csnum whitelist."
				jsonSafe, err := json.Marshal(user.LastIngameSN)
				return map[string]string{"success": "User Added", "name": string(jsonSafe)}
			}
			*message += "Bad Friend Code size"
			return map[string]string{"error": "bad size FC"}
		}

		if whitelisted {
			user, err := database.FetchUsernameAPI(pool, ctx, uint32(pid2))
			if err != nil {
				*message += "User is already on csnum whitelist."
				return map[string]string{"error": "Error, user is already whitelisted"}
			}
			*message += "User \"" + user.LastIngameSN + "\" is already on csnum whitelist."
			return map[string]string{"error": "Error, user is already whitelisted"}
		}
		*message += "Error while checking boolean (add)"
		return map[string]string{"error": "Error while checking boolean (add)"}

	case "Remove":
		if whitelisted {
			fcStr := query.Get("fc")
			if fcStr == "" {
				*message += "Friend Code missing"
				return map[string]string{"error": "missing FC"}
			}
			re := regexp.MustCompile("[^0-9]")
			fcstrint := re.ReplaceAllString(fcStr, "")
			fc, err := strconv.ParseUint(fcstrint, 10, 64)
			if err != nil {
				*message += "invalid conversion from Friend Code input"
				return map[string]string{"error": "bad conversion"}
			}
			if len(fcstrint) < 13 {
				pidd := fc & 0xffffffff
				fc2str := common.CalcFriendCodeString(uint32(pidd), "RMCJ")
				if fcStr != fc2str {
					*message += "Friend Code does match the format of \"Mario Kart Wii\""
					return map[string]string{"error": "bad FC, typo?"}
				}

				database.Removecsnumwhitelistf(pool, ctx, uint32(pidd))
				user, err := database.FetchUsernameAPI(pool, ctx, uint32(pidd))
				if err != nil {
					*message += "User Removed."
					return map[string]string{"success": "User Removed"}
				}

				*message += "User \"" + user.LastIngameSN + "\" Removed from csnum whitelist."
				jsonSafe, err := json.Marshal(user.LastIngameSN)
				if err != nil {
					return map[string]string{"success": "User Removed", "name": "bad name"}
				}
				return map[string]string{"success": "User Removed", "name": string(jsonSafe)}
			}
			*message += "Incorrect Friend Code Format"
			return map[string]string{"error": "bad size FC"}
		}

		if !whitelisted {
			*message += "User isn't on csnum whitelist, cannot remove."
			return map[string]string{"error": "User isn't whitelisted, cannot remove"}
		}
		*message += "Error while checking boolean, coding error?"
		return map[string]string{"error": "Error while checking boolean (remove)"}

	default:
		*message += "missing Add, Remove, from type"
		return map[string]string{"error": "missing Add or Remove"}
	}
}
