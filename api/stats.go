package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"wwfc/common"
	"wwfc/qr2"
	//"wwfc/gpcm"
)

var usedGameNames = []string{"mariokartwii"} // Initialize with "mariokartwii"

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
	restricted := []string{"publicip", "__session__", "localip0", "localip1", "+gppublicip", "+deviceauth", "+searchid", "+mii0", "+mii1"}

	// Initialize stats map to hold statistics for each game
	stats := make(map[string][]map[string]string)

	servers := qr2.GetSessionServers()

	// Iterate over the servers data
	for _, server := range servers {
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
				filteredServer[key] = value
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
				fmt.Println("Error converting PID to uint32:", err)
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

	// Include all used game names in the JSON response
	for _, game := range usedGameNames {
		if _, ok := stats[game]; !ok {
			// If there are no players in a game, add an empty list to the stats
			stats[game] = []map[string]string{}
		}
	}

	//testdata := map[uint32]*GameSpySession{}
	//fmt.Println(testdata)
	// Marshal stats to JSON
	jsonData, err := json.Marshal(stats)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println("Error marshalling JSON:", err)
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
	_, err = w.Write(jsonData)
	if err != nil {
		fmt.Println("Error writing JSON response:", err)
	}
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
