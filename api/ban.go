package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"wwfc/common"
	"wwfc/database"
	"wwfc/gpcm"
)

func HandleBan(w http.ResponseWriter, r *http.Request) {
	errorString := handleBanImpl(w, r)
	if errorString != "" {
		jsonData, _ := json.Marshal(map[string]string{"error": errorString})
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
}

func handleBanImpl(w http.ResponseWriter, r *http.Request) string {
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

	if apiSecret == "" || query.Get("secret") != apiSecret {
		return "Invalid API secret"
	}

	pidStr := query.Get("pid")
	if pidStr == "" {
		return "Missing pid in request"
	}

	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		return "Invalid pid"
	}

	tosStr := query.Get("tos")
	if tosStr == "" {
		return "Missing tos in request"
	}

	tos, err := strconv.ParseBool(tosStr)
	if err != nil {
		return "Invalid tos"
	}

	minutes := uint64(0)
	if query.Get("minutes") != "" {
		minutesStr := query.Get("minutes")
		minutes, err = strconv.ParseUint(minutesStr, 10, 32)
		if err != nil {
			return "Invalid minutes"
		}
	}

	hours := uint64(0)
	if query.Get("hours") != "" {
		hoursStr := query.Get("hours")
		hours, err = strconv.ParseUint(hoursStr, 10, 32)
		if err != nil {
			return "Invalid hours"
		}
	}

	days := uint64(0)
	if query.Get("days") != "" {
		daysStr := query.Get("days")
		days, err = strconv.ParseUint(daysStr, 10, 32)
		if err != nil {
			return "Invalid days"
		}
	}

	reason := query.Get("reason")
	if "reason" == "" {
		return "Missing ban reason"
	}

	// reason_hidden is optional
	reasonHidden := query.Get("reason_hidden")

	moderator := query.Get("moderator")
	if "moderator" == "" {
		moderator = "admin"
	}

	minutes = days*24*60 + hours*60 + minutes
	if minutes == 0 {
		return "Missing ban length"
	}

	length := time.Duration(minutes) * time.Minute

	if !database.BanUser(pool, ctx, uint32(pid), tos, length, reason, reasonHidden, moderator) {
		return "Failed to ban user"
	}

	if tos {
		gpcm.KickPlayer(uint32(pid), "banned")
	} else {
		gpcm.KickPlayer(uint32(pid), "restricted")
	}

	return ""
}

func HandleFetch(w http.ResponseWriter, r *http.Request) {
	result := handleAddRemoveTrusted(w, r)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	jsonResponse, err := json.Marshal(result)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}

	// Set Content-Length header
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonResponse)))

	w.Write(jsonResponse)
}

func handleAddRemoveTrusted(w http.ResponseWriter, r *http.Request) interface{} {
	// TODO: Actual authentication rather than a fixed secret
	// TODO: Use POST instead of GET
	var trusted bool
	var pid32 uint32
	u, err := url.Parse(r.URL.String())
	if err != nil {
		return map[string]string{"error": "Bad request"}
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return map[string]string{"error": "Bad request"}
	}

	if query.Get("key") != apiSecret {
		if query.Get("key") != apiTrusted {
			return map[string]string{"error": "Invalid API secret"}
		}
	}
	if apiSecret == "" || apiTrusted == "" {
		return map[string]string{"error": "Woops, haven't set up config"}

	}

	request := query.Get("type")
	if "type" == "" {
		return map[string]string{"error": "Missing Add or Remove or FETCH"}
	}
	if request != "FETCH" {
		pidStr := query.Get("pid")
		if pidStr == "" {
			return map[string]string{"error": "Missing pid in request"}
		}

		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			return map[string]string{"error": "Invalid pid"}
		}

		pid32 = uint32(pid)

		trusted, err = database.DoesUserTrusted(pool, ctx, pid32)
		if err != nil {
			return "An error occured"
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
	case "Add":
		if !trusted {
			_, err = database.AddTrusted(pool, ctx, pid32)
			if err != nil {
				return map[string]string{"error": "couldn't add user"}
			}
			return map[string]string{"success": "User Added"}
		}
		if trusted {
			return map[string]string{"error": "Error, user is already whitelisted"}
		}

		return map[string]string{"error": "Error while checking boolean (add)"}

	case "Remove":
		if trusted {
			database.RemoveTrusted(pool, ctx, pid32)
			return map[string]string{"success": "User Removed"}
		}

		if !trusted {
			return map[string]string{"error": "User isn't whitelisted, cannot remove"}
		}
		return map[string]string{"error": "Error while checking boolean (remove)"}

	default:
		return map[string]string{"error": "missing Add or Remove or FETCH"}
	}
}
