package gpcm

import (
	"strconv"
	"time"
	"wwfc/common"
	"wwfc/logging"
	"wwfc/qr2"
)

func kickPlayer(profileID uint32, reason string) {
	if session, exists := sessions[profileID]; exists {
		errorMessage := WWFCMsgKickedGeneric

		switch reason {
		case "banned":
			errorMessage = WWFCMsgProfileBannedTOSNow

		case "delbanned":
			errorMessage = WWFCMsgProfileBannedTOSNowDeluxe

		case "restartgame":
			errorMessage = WWFCMsgInvalidData

		case "alreadyregistered":
			errorMessage = WWFCMsgreregistered

		case "restricted":
			errorMessage = WWFCMsgProfileRestrictedNow

		case "restricted_join":
			errorMessage = WWFCMsgProfileRestricted

		case "untrusted":
			errorMessage = WWFCMsgProfileUntrusted

		case "moderator_kick":
			errorMessage = WWFCMsgKickedModerator

		case "room_kick":
			errorMessage = WWFCMsgKickedRoomHost

		case "invalid_elo":
			errorMessage = WWFCMsgInvalidELO

		case "network_error":
			// No error message
			common.CloseConnection(ServerName, session.ConnIndex)
			return
		}

		session.replyError(GPError{
			ErrorCode:   ErrConnectionClosed.ErrorCode,
			ErrorString: "The player was kicked from the server. Reason: " + reason,
			Fatal:       true,
			WWFCMessage: errorMessage,
		})
	}
}

func KickPlayer(profileID uint32, reason string) {
	mutex.Lock()
	defer mutex.Unlock()

	kickPlayer(profileID, reason)
}

func KickPlayerDel(profileID uint32, reason string, banlenght int64, publicreason string) {
	mutex.Lock()
	defer mutex.Unlock()
	if session, exists := sessions[profileID]; exists {
		session.User.BanLenght = banlenght
		session.User.Public_reason = publicreason
	}
	kickPlayer(profileID, reason)
}

func KickPlayerDelay(profileID uint32, reason string) {
	go func() {
		time.Sleep(5 * time.Second)
		mutex.Lock()
		defer mutex.Unlock()

		kickPlayer(profileID, reason)
	}()
}

func KickPlayerCustomMessage(profileID uint32, reason string, message WWFCErrorMessage) {
	mutex.Lock()
	defer mutex.Unlock()

	if session, exists := sessions[profileID]; exists {
		session.replyError(GPError{
			ErrorCode:   ErrConnectionClosed.ErrorCode,
			ErrorString: "The player was kicked from the server. Reason: " + reason,
			Fatal:       true,
			WWFCMessage: message,
			Reason:      reason,
		})
	}
}

func KickCommand(pid uint32) {

	msg := strconv.FormatUint(uint64(pid), 10)
	logging.Notice("Kick " + msg + " attempted")

	servers := qr2.GetSessionServers()
	if servers == nil {
		return
	}
	AmountHosts := 0
	AmountNormal := 0
	Ishost := false
	for _, server := range servers {
		//check if server is nil specifically
		if server == nil {
			continue
		}
		if server["gamename"] == "" {
			continue
		}
		if server["gamename"] != "mariokartwii" {
			continue
		}
		if server["dwc_pid"] == "" {
			continue
		}
		//if server["rk"] == "" {
		//	continue
		//}
		if server["dwc_groupid"] == "" {
			continue
		}
		if server["dwc_groupid"] == "0" {
			if server["rk"] == "" {
				continue
			}
			if len(server["rk"]) < 4 {
				continue
			}
			if server["rk"][3:] != "760" {
				continue
			}
		} else {
			Ishost = true
		}
		hostint, err := strconv.ParseUint(server["dwc_pid"], 10, 32)
		if err != nil {
			logging.Error("Error converting PID to int:\n", err)
			continue // Skip to the next server if there's an error
		}
		host := uint32(hostint)
		ok := SendKickMessageToProfileId("1", host, msg)
		if ok {
			if Ishost == true {
				AmountHosts += 1
				logging.Notice("Kick message sent to room host: " + strconv.FormatUint(uint64(host), 10))
			} else {
				AmountNormal += 1
				logging.Notice("Kick message sent to normal player: " + strconv.FormatUint(uint64(host), 10))
			}

		} else {
			logging.Notice("Kick message failed, pid: " + strconv.FormatUint(uint64(host), 10))
		}
	}
	logging.Notice("Sent to " + strconv.FormatUint(uint64(AmountHosts), 10) + " hosts")
	logging.Notice("Sent to " + strconv.FormatUint(uint64(AmountNormal), 10) + " normal players")
}
