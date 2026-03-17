package serverbrowser

import (
	"strconv"
	"strings"
	"time"
	"wwfc/gpcm"
	"wwfc/logging"
	"wwfc/qr2"
	"wwfc/serverbrowser/filter"

	"github.com/logrusorgru/aurora/v3"
)

// DWC makes requests in the following formats:
// Matching ver 03: dwc_mver = %d and dwc_pid != %u and maxplayers = %d and numplayers < %d and dwc_mtype = %d and dwc_hoststate = %u and dwc_suspend = %u and (%s)
// Matching ver 90: dwc_mver = %d and dwc_pid != %u and maxplayers = %d and numplayers < %d and dwc_mtype = %d and dwc_mresv != dwc_pid and (%s)
// ...OR
// Self Lookup: dwc_pid = %u

// Example: dwc_mver = 90 and dwc_pid != 43 and maxplayers = 11 and numplayers < 11 and dwc_mtype = 0 and dwc_hoststate = 2 and dwc_suspend = 0 and (rk = 'vs' and ev >= 4250 and ev <= 5750 and p = 0)

func filterServers(moduleName string, servers []map[string]string, queryGame string, expression string, publicIP string) []map[string]string {
	// Matchmaking search
	tree, err := filter.Parse(expression)
	if err != nil {
		logging.Error(moduleName, "Error parsing filter:", err.Error())
		return []map[string]string{}
	}

	var filtered []map[string]string

	for _, server := range servers {
		if server["gamename"] != queryGame {
			continue
		}

		if server["+deviceauth"] != "1" {
			continue
		}

		if server["dwc_mver"] == "90" && (server["dwc_hoststate"] != "0" && server["dwc_hoststate"] != "2") {
			continue
		}

		if server["gamename"] == "mariokartwii" {
			if server["rk"] != "" && len(server["rk"]) > 2 {
				if rk, err := strconv.Atoi(server["rk"][3:]); err == nil {
					//if server["+DB"] == "true" && (strings.HasPrefix(server["rk"], "vs_760") || strings.HasPrefix(server["rk"], "bt_760") || strings.HasPrefix(server["rk"], "vs_825") || strings.HasPrefix(server["rk"], "bt_825")) { //|| strings.HasPrefix(server["rk"], "cp") || (len(server["rk"]) == 4 && server["rk"][3] >= '0' && server["rk"][3] < '6') {
					if server["+DB"] == "true" && rk != 191 && rk != 866 && (rk >= 7 && rk < 20000) { //PP bans //760
						//ret = 0
						// Check if the value exists
						dwcPidStr, ok := server["dwc_pid"]

						if !ok {
							// Handle the case when dwc_pid key does not exist
							continue
						}

						// Convert string to int
						dwcPidInt, err := strconv.Atoi(dwcPidStr)
						if err != nil {
							// Handle the case when dwc_pid cannot be converted to int
							continue
						}

						// Convert int to int32
						dwcPid := int32(dwcPidInt)
						gpcm.KickPlayer(uint32(dwcPid), "delbanned") //PP //NoMutex thing
						//qr2.PayloadUser(uint32(dwcPid))
						continue

					}
					if server["+csnum"] == "" && rk == 760 { //deluxe csnum check
						// Check if the value exists
						dwcPidStr, ok := server["dwc_pid"]
						if !ok {
							// Handle the case when dwc_pid key does not exist
							continue
						}
						// Convert string to int
						dwcPidInt, err := strconv.Atoi(dwcPidStr)
						if err != nil {
							// Handle the case when dwc_pid cannot be converted to int
							continue
						}
						dwcPid := int32(dwcPidInt)
						gpcm.KickPlayer(uint32(dwcPid), "restartgame") //PP //NoMutex thing
						//qr2.PayloadUser(uint32(dwcPid))
						continue
					} else if server["+csnum"] == "0" && rk == 760 {
						// Check if the value exists
						dwcPidStr, ok := server["dwc_pid"]
						if !ok {
							// Handle the case when dwc_pid key does not exist
							continue
						}
						// Convert string to int
						dwcPidInt, err := strconv.Atoi(dwcPidStr)
						if err != nil {
							// Handle the case when dwc_pid cannot be converted to int
							continue
						}
						dwcPid := int32(dwcPidInt)
						gpcm.KickPlayer(uint32(dwcPid), "alreadyregistered") //PP //NoMutex thing
						//qr2.PayloadUser(uint32(dwcPid))
						continue
					}
				}
			}

			if strings.HasPrefix(server["rk"], "vp") || strings.HasPrefix(server["rk"], "bp") || strings.HasPrefix(server["rk"], "cp") || (len(server["rk"]) == 4 && server["rk"][3] >= '0' && server["rk"][3] < '6') {
				if server["+trusted"] == "false" {
					//ret = 0
					// Check if the value exists
					dwcPidStr, ok := server["dwc_pid"]

					if !ok {
						// Handle the case when dwc_pid key does not exist
						continue
					}

					// Convert string to int
					dwcPidInt, err := strconv.Atoi(dwcPidStr)
					if err != nil {
						// Handle the case when dwc_pid cannot be converted to int
						continue
					}

					// Convert int to int32
					dwcPid := int32(dwcPidInt)

					gpcm.PayloadUser(uint32(dwcPid))
					qr2.PayloadUserTrusted(uint32(dwcPid))
					logging.Notice("payloaded filter")
					//gpcm.KickPlayerDelay(uint32(dwcPid), "untrusted") //PP //NoMutex thing
					go func() {
						time.Sleep(3 * time.Second)
						gpcm.KickPlayer(uint32(dwcPid), "untrusted") //PP //NoMutex thing
					}()
					continue

				}
			}
		}

		ret, err := filter.Eval(tree, server, queryGame)
		if err != nil {
			logging.Error(moduleName, "Error evaluating filter:", err.Error())
			return []map[string]string{}
		}

		if ret != 0 {
			filtered = append(filtered, server)
		}
	}

	if len(filtered) != 0 {
		logging.Info(moduleName, "Matched", aurora.BrightCyan(len(filtered)), "servers")
	}

	return filtered
}

func filterSelfLookup(moduleName string, servers []map[string]string, queryGame string, dwcPid string, publicIP string) []map[string]string {
	var filtered []map[string]string

	// Search for where the profile ID matches
	for _, server := range servers {
		if server["gamename"] != queryGame {
			continue
		}

		if server["dwc_pid"] == dwcPid {
			// May not be a self lookup, some games search for friends like this
			logging.Info(moduleName, "Lookup", aurora.Cyan(dwcPid), "ok")
			return []map[string]string{server}
		}

		// Alternatively, if the server hasn't set its dwc_pid field yet, we return servers matching the request's public IP.
		// If multiple servers exist with the same public IP then the client will use the one with the matching port.
		// This is a bit of a hack to speed up server creation.
		if _, ok := server["dwc_pid"]; !ok && server["publicip"] == publicIP {
			// Create a copy of the map with some values changed
			newServer := map[string]string{}
			for k, v := range server {
				newServer[k] = v
			}
			newServer["dwc_pid"] = dwcPid
			newServer["dwc_mtype"] = "0"
			newServer["dwc_mver"] = "0"
			filtered = append(filtered, newServer)
		}
	}

	if len(filtered) == 0 {
		logging.Error(moduleName, "Could not find server with dwc_pid", aurora.Cyan(dwcPid))
		return []map[string]string{}
	}

	logging.Info(moduleName, "Self lookup for", aurora.Cyan(dwcPid), "matched", aurora.BrightCyan(len(filtered)), "servers via public IP")
	return filtered
}
