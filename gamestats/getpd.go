package gamestats

import (
	"strconv"
	"time"
	"wwfc/common"
)

func (g *GameStatsSession) getpd(command common.GameSpyCommand) {
	g.Write(common.GameSpyCommand{
		Command:      "getpdr",
		CommandValue: "1",
		OtherValues: map[string]string{
			"lid":    strconv.Itoa(g.LoginID),
			"pid":    command.OtherValues["pid"],
			"mod":    strconv.Itoa(int(time.Now().Unix())),
			"length": "0",
			"data":   `\\`,
		},
	})
}
