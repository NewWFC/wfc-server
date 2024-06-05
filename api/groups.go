package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"wwfc/qr2"
)

func HandleGroups(w http.ResponseWriter, r *http.Request) {
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

	groups := qr2.GetGroups(query["game"], query["id"], true)

	var jsonData []byte
	if len(groups) == 0 {
		jsonData, _ = json.Marshal([]string{})
	} else {
		jsonData, err = json.Marshal(groups)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
	w.Write(jsonData)
}

//func HandleJson(w http.ResponseWriter, r *http.Request) {
//	return
//}
//u, err := url.Parse(r.URL.String())
//if err != nil {
//	w.WriteHeader(http.StatusBadRequest)
//	return
//}

//query, err := url.ParseQuery(u.RawQuery)
//if err != nil {
//	w.WriteHeader(http.StatusBadRequest)
//	return
//}

//group := qr2.GetGroups(query["game"], query["id"], true)

// Remove restricted fields and process "dwc_pid" for each server
////// Assuming servers are directly accessible within the group
//if err != nil { //for _, server := range { // Adjust this line based on the actual structure of qr2.GroupInfo
// Remove restricted fields
//server := 1
//delete(server, "publicip")
//delete(server, "__session__")
//delete(server, "localip0")
//delete(server, "localip1")

// Check if "dwc_pid" is present
//dwc_pid, ok := server["dwc_pid"].(string)
//if ok && dwc_pid != "" {
// Process "dwc_pid"
//    server["FC"] = "Loading..."
//} else {
//    server["FC"] = "Loading..."
//}
//}

// Marshal the modified group into JSON format and send it as the HTTP response
//jsonData, err := json.Marshal(group)
//if err != nil {
//	w.WriteHeader(http.StatusInternalServerError)
//	return
//}

//w.Header().Set("Content-Type", "application/json")
//w.Header().Set("Access-Control-Allow-Origin", "*")
//w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
//w.Write(jsonData)
//}
