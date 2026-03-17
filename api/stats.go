package api

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"wwfc/common"
	"wwfc/database"
	"wwfc/gpcm"
	"wwfc/logging"
	"wwfc/qr2"
)

var (
	usedGameNames = []string{"mariokartds", "mariokartwii"} // Initialize with "mariokartwii"
	mutex         = sync.RWMutex{}
)

type Stats struct {
	OnlinePlayerCount int `json:"online"`
	ActivePlayerCount int `json:"active"`
	GroupCount        int `json:"groups"`
}

func HandleStats(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	games := query["game"]

	stats := map[string]Stats{}

	servers := qr2.GetSessionServers()
	groups := qr2.GetGroups([]string{}, []string{}, false)

	globalStats := Stats{
		OnlinePlayerCount: len(servers),
		ActivePlayerCount: 0,
		GroupCount:        len(groups),
	}

	for _, server := range servers {
		gameName := server["gamename"]

		if server["+joinindex"] != "" {
			globalStats.ActivePlayerCount += 1
		}

		if len(games) > 0 && !common.StringInSlice(gameName, games) {
			continue
		}

		gameStats, exists := stats[gameName]
		if !exists {
			gameStats = Stats{
				OnlinePlayerCount: 0,
				ActivePlayerCount: 0,
				GroupCount:        0,
			}

			for _, group := range groups {
				if group.GameName == gameName {
					gameStats.GroupCount += 1
				}
			}
		}

		gameStats.OnlinePlayerCount += 1
		if server["+joinindex"] != "" {
			gameStats.ActivePlayerCount += 1
		}

		stats[gameName] = gameStats
	}

	stats["global"] = globalStats

	jsonData, err := json.Marshal(stats)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
	w.Write(jsonData)
}

func HandleJson(w http.ResponseWriter, r *http.Request) {
	// Define restricted fields to be removed
	restricted := []string{"publicip", "__session__", "localip0", "localip1", "+gppublicip", "+deviceauth", "+searchid", "+mii0", "+mii1", "+csnum"}

	// Initialize stats map to hold statistics for each game
	stats := make(map[string][]map[string]string)

	servers := qr2.GetSessionServers()
	//gpcm := gpcm.GetSessionServers()

	// check if servers is nil for some reason
	if servers == nil {
		// Instead of returning an error, return all usedGameNames as keys with empty arrays
		stats := make(map[string][]map[string]string)
		for _, game := range usedGameNames {
			stats[game] = []map[string]string{}
		}
		jsonData, err := json.Marshal(stats)
		if err != nil {
			http.Error(w, "Internal server error, Error converting data to JSON", http.StatusInternalServerError)
			logging.Error("Error marshalling JSON:\n", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache") // HTTP/1.0 backward compatibility
		w.Header().Set("Expires", "0")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self';")
		_, err = w.Write(jsonData)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			logging.Error("Internal server error, Couldn't write jsondata to w.Write\n", err)
		}
		return
	}
	// if servers == nil {
	// 	http.Error(w, "Internal server error, 'servers' is nil", http.StatusInternalServerError)
	// 	logging.Error("Internal server error, 'servers' is nil")
	// 	return
	// }
	// Iterate over the servers data
	mutex.Lock()
	for _, server := range servers {
		//check if server is nil specifically
		if server == nil {
			http.Error(w, "Internal server error, 'server' is nil", http.StatusInternalServerError)
			logging.Error("Internal server error, 'server' is nil")
			mutex.Unlock()
			return
		}
		game := server["gamename"]
		// Check if the game name is already a key in the stats map
		// If not, create a new entry for the game
		if _, ok := stats[game]; !ok {
			stats[game] = make([]map[string]string, 0)
		}

		// Filter out restricted keys from the server data
		filteredServer := make(map[string]string)
		for key, value := range server {
			if !contains(restricted, key) {
				filteredServer[key] = html.EscapeString(value)
			}
		}

		// Add filtered server data to the stats map for the current game
		stats[game] = append(stats[game], filteredServer)

		// Calculate FC and add it to the filtered server data
		pid := filteredServer["dwc_pid"]
		if pid != "" {
			gameId := filteredServer["+fcgameid"]
			pidUint32, err := strconv.ParseUint(pid, 10, 32)
			if err != nil {
				logging.Error("Error converting PID to uint32:\n", err)
				continue // Skip to the next server if there's an error
			}
			fc := common.CalcFriendCodeString(uint32(pidUint32), gameId)
			filteredServer["FC"] = fc
		}

		// Add the game to usedGameNames if it's not already present

		if game != "mariokartwii" && !contains(usedGameNames, game) {
			usedGameNames = append(usedGameNames, game)
		}

	}
	mutex.Unlock()

	// Include all used game names in the JSON response
	mutex.Lock()
	for _, game := range usedGameNames {
		if _, ok := stats[game]; !ok {
			// If there are no players in a game, add an empty list to the stats
			stats[game] = []map[string]string{}
		}
	}
	mutex.Unlock()
	//fmt.Println(testdata)
	// Marshal stats to JSON
	jsonData, err := json.Marshal(stats)
	if err != nil {
		http.Error(w, "Internal server error, Error converting data to JSON", http.StatusInternalServerError)
		//w.WriteHeader(http.StatusInternalServerError)
		logging.Error("Error marshalling JSON:\n", err)
		return
	}

	//var count int
	count := len(gpcm.GetSessionServers())

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	//thing
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache") // HTTP/1.0 backward compatibility
	w.Header().Set("Expires", "0")
	w.Header().Set("X-PlayersGPCM", strconv.Itoa(count))                                                                      // Ensure the response is treated as expired
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self';") // allow fetching in console

	_, err = w.Write(jsonData)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		logging.Error("Internal server error, Couldn't write jsondata to w.Write\n", err)
	}
}

func HandleTimeTrials(w http.ResponseWriter, r *http.Request) {
	result := handleTimeTrialsz(w, r)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")                                                                                      // HTTP/1.0 backward compatibility
	w.Header().Set("Expires", "0")                                                                                            // Ensure the response is treated as expired
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self';") //allow fetching in console

	jsonResponse, err := json.Marshal(result)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}

	// Set Content-Length header
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonResponse)))

	w.Write(jsonResponse)
}

func handleTimeTrialsz(w http.ResponseWriter, r *http.Request) interface{} {
	// TODO: Actual authentication rather than a fixed secret
	// TODO: Use POST instead of GET
	var hidden bool
	//var trackid int
	//var pid32 uint32

	u, err := url.Parse(r.URL.String())
	if err != nil {
		return map[string]string{"error": "Bad request"}
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return map[string]string{"error": "Bad request"}
	}

	//request := query.Get("none")
	//if "track" == "" {
	//	return map[string]string{"error": "Missing track"}
	//}

	trackidStr := query.Get("track")
	if trackidStr == "" {
		return map[string]string{"error": "Missing track in request"}
	}
	trackid64, err := strconv.ParseUint(trackidStr, 10, 8)
	if err != nil {
		return map[string]string{"error": "Invalid track"}
	}

	hiddenStr := query.Get("hidden")

	if hiddenStr != "" && hiddenStr == "true" {
		hidden = true
	} else {
		hidden = false
	}
	var region uint8
	trackid := uint8(trackid64)

	if trackid >= 31 {
		return map[string]string{"error": "Invalid Track"}
	}

	region = 0 //force no region

	// look at race server nintendo_racing_service.go
	//type rankingsRequestEnvelope struct {
	//	Body rankingsRequestBody
	//}

	//type rankingsRequestBody struct {
	//	Data rankingsRequestData `xml:",any"`
	//}

	trackresults, err := database.TimeTrials(pool, ctx, region, trackid, hidden) //int(trackid), hidden)
	if err != nil {
		fmt.Println(err)
		logging.Error("Error querying database:\n", err)
		return map[string]string{"error": "database error"}
	}

	return trackresults
	//fmt.Println(trackresults)
	//fmt.Println(trackid)

	//if query.Get("hidden") != apiSecret {
	//	if query.Get("hidden") != apiTrusted {
	//		return map[string]string{"error": "Invalid API secret"}
	//	}
	//}

	//return map[string]string{"error": "end"}
}

func HandleGPCMFetch(w http.ResponseWriter, r *http.Request) {
	result := HandleJsonAdmin(w, r)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")                                                                                      // HTTP/1.0 backward compatibility
	w.Header().Set("Expires", "0")                                                                                            // Ensure the response is treated as expired
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self';") //allow fetching in console

	jsonResponse, err := json.Marshal(result)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		logging.Error("Error encoding JSON:\n", err)
		return
	}

	// Set Content-Length header
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonResponse)))

	w.Write(jsonResponse)
}

func HandleJsonAdmin(w http.ResponseWriter, r *http.Request) interface{} {
	// Define restricted fields to be removed
	//restricted := []string{"publicip", "__session__", "localip0", "localip1", "+gppublicip", "+deviceauth", "+searchid", "+mii0", "+mii1"}
	//restricted := []string{}

	// Initialize stats map to hold statistics for each game
	//stats := make(map[string][]map[string]string)
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

	servers := gpcm.GetSessionServers()

	// Iterate over the servers data
	// for _, server := range servers {
	// 	game := server["gamename"]
	// 	// Check if the game name is already a key in the stats map
	// 	// If not, create a new entry for the game
	// 	if _, ok := stats[game]; !ok {
	// 		stats[game] = make([]map[string]string, 0)
	// 	}

	// 	// Filter out restricted keys from the server data
	// 	filteredServer := make(map[string]string)
	// 	for key, value := range server {
	// 		if !contains(restricted, key) {
	// 			filteredServer[key] = html.EscapeString(value)
	// 		}
	// 	}

	// 	// Add filtered server data to the stats map for the current game
	// 	stats[game] = append(stats[game], filteredServer)

	// 	// Calculate FC and add it to the filtered server data
	// 	pid := filteredServer["dwc_pid"]
	// 	if pid != "" {
	// 		gameId := filteredServer["+fcgameid"]
	// 		pidUint32, err := strconv.ParseUint(pid, 10, 32)
	// 		if err != nil {
	// 			fmt.Println("Error converting PID to uint32:", err)
	// 			continue // Skip to the next server if there's an error
	// 		}
	// 		fc := common.CalcFriendCodeString(uint32(pidUint32), gameId)
	// 		filteredServer["FC"] = fc
	// 	}

	// 	// Add the game to usedGameNames if it's not already present
	// 	if game != "mariokartwii" && !contains(usedGameNames, game) {
	// 		usedGameNames = append(usedGameNames, game)
	// 	}
	// }

	// // Include all used game names in the JSON response
	// for _, game := range usedGameNames {
	// 	if _, ok := stats[game]; !ok {
	// 		// If there are no players in a game, add an empty list to the stats
	// 		stats[game] = []map[string]string{}
	// 	}
	// }

	// testdata := map[uint32]*GameSpySession{}
	// fmt.Println(testdata)
	// Marshal stats to JSON
	if servers == nil {
		return map[string]string{"error": "no logins?"}
	}
	return servers
}

//func HandleJson(w http.ResponseWriter, r *http.Request) {
// Get the server list from qr2.GetSessionServers()
//	serverList := qr2.GetSessionServers()

// Create a copy of the server list to avoid modifying the original data
//	copyServerList := make([]map[string]string, len(serverList))
//	copy(copyServerList, serverList)

// Define restricted fields to be removed
//	restrictedList := []string{"publicip", "__session__", "localip0", "localip1", "+gppublicip", "+deviceauth", "+searchid"}

// Initialize a map to store servers per game
//	gameServersList := make(map[string][]map[string]string)

// Group servers by gamename and add FC
//	for _, serverjson := range copyServerList {
//		gameNameList := serverjson["gamename"] //+fcgameid"]
// Remove restricted fields
//		for _, r := range restrictedList {
//			delete(serverjson, r) //temp
//fmt.Println(r)
//		}
// Convert dwc_pid to uint32
//		dwcPIDStr := serverjson["dwc_pid"]
//		dwcPID, err := strconv.ParseUint(dwcPIDStr, 10, 32)
//		if err != nil {
// Handle the error (e.g., log it, return an error response)
//			return
//		}
//		// Calculate FC
//		gameIDJSON := serverjson["+fcgameid"]
//		FC := common.CalcFriendCode(uint32(dwcPID), gameIDJSON)
// Convert FC to string and format with dashes every 4 numbers
//		FCStr := strconv.FormatUint(uint64(FC), 10)
//		formattedFC := formatFriendCode(FCStr)
//		// Add formatted FC to server information
//		serverjson["FC"] = formattedFC

// Add server to corresponding game group
//		gameServersList[gameNameList] = append(gameServersList[gameNameList], serverjson)
//	}

// Convert the grouped server list to JSON
//	output, err := json.Marshal(gameServersList)
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}

// Set response headers
//	w.Header().Set("Content-Type", "application/json")
//	w.Header().Set("Access-Control-Allow-Origin", "*")
//	w.Header().Set("Content-Length", strconv.Itoa(len(output)))

// Write the JSON response
//	w.Write(output)
//}

func formatFriendCode(FCStr string) string {
	var formattedFC string
	for i, c := range FCStr {
		if i > 0 && i%4 == 0 {
			formattedFC += "-"
		}
		formattedFC += string(c)
	}
	return formattedFC
}

// Helper function to check if a string exists in a slice of strings
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
