package qr2

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"
	"wwfc/acommon"
	"wwfc/common"
	"wwfc/logging"

	"github.com/logrusorgru/aurora/v3"
)

func heartbeat(moduleName string, conn net.PacketConn, addr net.UDPAddr, buffer []byte) {
	sessionId := binary.BigEndian.Uint32(buffer[1:5])
	values := strings.Split(string(buffer[5:]), "\u0000")

	payload := map[string]string{}
	unknowns := []string{}
	for i := 0; i < len(values)-1; i += 2 {
		if len(values[i]) == 0 || values[i][0] == '+' {
			continue
		}

		if values[i] == "unknown" {
			unknowns = append(unknowns, values[i+1])
			continue
		}

		payload[values[i]] = values[i+1]
	}

	if payload["dwc_mtype"] != "" {
		logging.Info(moduleName, "Match type:", aurora.Cyan(payload["dwc_mtype"]))
	}

	if payload["dwc_hoststate"] != "" {
		logging.Info(moduleName, "Host state:", aurora.Cyan(payload["dwc_hoststate"]))
	}

	realIP, realPort := common.IPFormatToString(addr.String())

	noIP := false
	if ip, ok := payload["publicip"]; !ok || ip == "0" {
		noIP = true
	}

	clientEndianness := common.GetExpectedUnitCode(payload["gamename"])
	if !noIP && clientEndianness == ClientBigEndian {
		if payload["publicip"] != realIP || payload["publicport"] != realPort {
			// Client is mistaken about its public IP
			logging.Error(moduleName, "Public IP mismatch")
			return
		}
	} else if !noIP && clientEndianness == ClientLittleEndian {
		realIPLE, realPortLE := common.IPFormatToStringLE(addr.String())
		if payload["publicip"] != realIPLE || payload["publicport"] != realPortLE {
			// Client is mistaken about its public IP
			logging.Error(moduleName, "Public IP mismatch")
			return
		}
	}
	// Else it's a cross-compatible game and the endianness is ambiguous

	payload["publicip"] = realIP
	payload["publicport"] = realPort

	lookupAddr := makeLookupAddr(addr.String())

	statechanged, ok := payload["statechanged"]
	if ok && statechanged == "2" {
		if payload["gamename"] == "mariokartds" {
			logging.Notice(moduleName, "Client session shutdown command from MARIO KART DS !!!!!!!!!!!!!!!!")
			mutex.Lock()
			session, exists := getSessionFromAddr(lookupAddr)
			if exists {
				if session.Data["numplayers"] == "0" || session.Data["+suspend"] == "true" {
					session.Data["+suspend"] = ""
					delete(session.Data, "+suspend")
					session.Data["kart_elo"] = "" //yes, I'm doing this to prevent server panic //PP
					delete(session.Data, "kart_elo")
					session.Data["kart_filter"] = ""
					delete(session.Data, "kart_filter")
					session.Data["kart_region"] = ""
					delete(session.Data, "kart_region")
					session.Data["kart_type"] = ""
					delete(session.Data, "kart_type")
					session.Data["+state"] = ""
					RemoveSessionGroup(lookupAddr)
					logging.Notice(moduleName, "unlock in exists 1")
					mutex.Unlock()
				} else {
					mutex.Unlock()
					go func() {
						//code here

						dwcpid, err := strconv.ParseUint(session.Data["dwc_pid"], 10, 32)
						if err != nil {
							return
						}
						//logging.Notice(moduleName, session.Data["+suspend"])
						if session.Data["+suspend"] != "true" {
							time.Sleep(1 * time.Second)
							state, ok := acommon.GetStateGPCM(uint32(dwcpid))
							if !ok {
								logging.Notice(moduleName, "notok1")
								return
							}
							mutex.Lock()
							defer mutex.Unlock()
							logging.Notice(moduleName, "defer")
							//expects mutex to be locked
							session, exists := getSessionFromAddr(lookupAddr)
							if !exists {
								logging.Notice(moduleName, "notok2")
								return
							}
							logging.Notice(moduleName, "state test 3:4 : ", state[3:4])
							if state[3:4] == "2" {
								session.Data["+state"] = state[3:4]
								session.Data["+suspend"] = "true"

								return
							}

							return
						} else {
							logging.Notice(moduleName, "else go funciton")
							mutex.Lock()
							defer mutex.Unlock()
							//expects mutex to be locked
							session, exists := getSessionFromAddr(lookupAddr)
							if !exists {
								return
							}
							session.Data["+state"] = ""
							//session.Data["+state"] = state[3:4]
							session.Data["+suspend"] = ""
							delete(session.Data, "+suspend")
							session.Data["kart_elo"] = ""
							delete(session.Data, "kart_elo")
							session.Data["kart_filter"] = ""
							delete(session.Data, "kart_filter")
							session.Data["kart_region"] = ""
							delete(session.Data, "kart_region")
							session.Data["kart_type"] = ""
							delete(session.Data, "kart_type")
							session.Data["numplayers"] = "0"
							RemoveSessionGroup(lookupAddr)
							return
						}
					}()

				}
				logging.Notice(moduleName, "return but after exists so yeah")
				return
			}
			mutex.Unlock()
			return
			//logging.Notice(moduleName, "state test MKDS!!!!!!!!!!!!!!: ", state)
		}
		logging.Notice(moduleName, "Client session shutdown")
		mutex.Lock()
		removeSession(lookupAddr)
		mutex.Unlock()
		return
	}

	if ratingError := checkValidRating(moduleName, payload); ratingError != "ok" {
		mutex.Lock()
		session, sessionExists := sessions[lookupAddr]
		if sessionExists && session.login != nil {
			profileId := session.login.ProfileID

			mutex.Unlock()
			gpErrorCallback(profileId, ratingError)
			return
		} else {
			// Else don't return and move on, so we can return an error once logged in
			mutex.Unlock()
		}
	}

	session, ok := setSessionData(moduleName, &addr, sessionId, payload)
	if !ok {
		return
	}

	if len(unknowns) > 0 {
		// Try to login using the first unknown as a profile ID
		// This makes it possible to execute the exploit on the client sooner

		mutex.Lock()
		sessionPtr, sessionExists := sessions[lookupAddr]
		if !sessionExists {
			logging.Error(moduleName, "Session not found")
		} else if sessionPtr.login == nil {
			profileId := unknowns[0]
			logging.Info(moduleName, "Attempting to use unknown as profile ID", aurora.Cyan(profileId))
			sessionPtr.setProfileID(moduleName, profileId, "")
		}
		session = *sessionPtr
		mutex.Unlock()
	}

	if !session.Authenticated || noIP {
		sendChallenge(conn, addr, session, lookupAddr)
	}

	if login := session.login; !session.ExploitReceived && login != nil && session.login.NeedsExploit {
		// The version of DWC in Mario Kart DS doesn't check matching status
		if (!noIP && statechanged == "1") || login.GameCode == "AMCE" || login.GameCode == "AMCP" || login.GameCode == "AMCJ" {
			logging.Notice(moduleName, "Sending SBCM exploit to DNS patcher client")
			sendClientExploit(moduleName, session)
		}
	}

	mutex.Lock()
	if session.groupPointer != nil {
		if session.groupPointer.server == nil {
			session.groupPointer.findNewServer()
		} else {
			// Update the match type if needed
			session.groupPointer.updateMatchType()
		}
	}
	mutex.Unlock()
}

func checkValidRating(moduleName string, payload map[string]string) string {
	if payload["gamename"] != "mariokartwii" {
		return "ok"
	}

	if public, isBattle := isPublicMatchRegion(payload["rk"]); public {
		// ev and eb values must be in range 1 to 9999
		if ev := payload["ev"]; !isBattle && ev != "" {
			evInt, err := strconv.ParseInt(ev, 10, 16)
			if err != nil || evInt < 0 || evInt > 999999 {
				logging.Error(moduleName, "Invalid ev value:", aurora.Cyan(ev))
				return "invalid_elo"
			}
		} else if eb := payload["eb"]; isBattle && eb != "" {
			ebInt, err := strconv.ParseInt(eb, 10, 16)
			if err != nil || ebInt < 0 || ebInt > 999999 {
				logging.Error(moduleName, "Invalid eb value:", aurora.Cyan(eb))
				return "invalid_elo"
			}
		}
	}
	return "ok"
}

func isPublicMatchRegion(rk string) (bool, bool) {
	if rk == "vs" {
		return true, false
	} else if rk == "bt" {
		return true, true
	} /*else if len(rk) == 4 && rk[3] >= '0' && rk[3] < '6' {
		if strings.HasPrefix(rk, "vs_") {
			return true, false
		} else if strings.HasPrefix(rk, "bt_") {
			return true, true
		}
	} */
	return false, false
}
