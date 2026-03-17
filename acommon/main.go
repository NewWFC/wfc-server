package acommon

// GameSpySession type as previously defined
type GameSpySession struct {
	User struct {
		ProfileId uint32
	}
	Status string
}

// Declare the function signature for the GetStateGPCM function.
var GetStateGPCMFunc func(uint32) (string, bool)

// Set the function via this setter.
func SetGetStateGPCMFunc(fn func(uint32) (string, bool)) {
	GetStateGPCMFunc = fn
}

// Call GetStateGPCM using the injected function.
func GetStateGPCM(dwc_pid uint32) (string, bool) {
	if GetStateGPCMFunc != nil {
		return GetStateGPCMFunc(dwc_pid)
	}
	return "", false
}

// KickPlayerFuncType defines the expected signature
type KickPlayerFuncType func(profileID uint32, reason string)

// KickPlayerFuncType defines the expected signature
type KickPlayerDelFuncType func(profileID uint32, reason string, banlenght int64, message string)

// Internal var to hold the actual function
var kickPlayerFunc KickPlayerFuncType

// Internal var to hold the actual function
var kickPlayerDelFunc KickPlayerDelFuncType

// SetKickPlayerFunc sets the implementation
func SetKickPlayerFunc(fn KickPlayerFuncType) {
	kickPlayerFunc = fn
}

func SetKickPlayerDelFunc(fn KickPlayerDelFuncType) {
	kickPlayerDelFunc = fn
}

// KickPlayer uses the injected function
func KickPlayer(profileID uint32, reason string) {
	if kickPlayerFunc != nil {
		kickPlayerFunc(profileID, reason)
	}
}

func KickPlayerDel(profileID uint32, reason string, banlenght int64, message string) {
	if kickPlayerDelFunc != nil {
		kickPlayerDelFunc(profileID, reason, banlenght, message)
	}
}
