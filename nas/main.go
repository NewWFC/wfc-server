package nas

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"wwfc/api"
	"wwfc/common"
	"wwfc/gamestats"
	"wwfc/logging"
	"wwfc/nhttp"
	"wwfc/race"
	"wwfc/sake"

	"github.com/logrusorgru/aurora/v3"
)

var (
	serverName           string
	server               *nhttp.Server
	payloadServerAddress string
)

func StartServer(reload bool) {
	// Get config
	config := common.GetConfig()

	serverName = config.ServerName

	address := *config.NASAddress + ":" + config.NASPort

	payloadServerAddress = config.PayloadServerAddress

	if config.EnableHTTPS {
		go startHTTPSProxy(config)
	}

	err := CacheProfanityFile()
	if err != nil {
		logging.Info("NAS", err)
	}

	server = &nhttp.Server{
		Addr:        address,
		Handler:     http.HandlerFunc(handleRequest),
		IdleTimeout: 20 * time.Second,
		ReadTimeout: 10 * time.Second,
	}

	go func() {
		logging.Notice("NAS", "Starting HTTP server on", aurora.BrightCyan(address))

		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, nhttp.ErrServerClosed) {
			panic(err)
		}
	}()
}

func Shutdown() {
	if server == nil {
		return
	}

	ctx, release := context.WithTimeout(context.Background(), 10*time.Second)
	defer release()

	err := server.Shutdown(ctx)
	if err != nil {
		logging.Error("NAS", "Error on HTTP shutdown:", err)
	}
}

var regexRaceHost = regexp.MustCompile(`^([a-z\-]+\.)?race\.gs\.`)
var regexSakeHost = regexp.MustCompile(`^([a-z\-]+\.)?sake\.gs\.`)
var regexGamestatsHost = regexp.MustCompile(`^([a-z\-]+\.)?gamestats2?\.gs\.`)
var regexStage1URL = regexp.MustCompile(`^/w([0-9])$`)

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Check for *.sake.gs.* or sake.gs.*
	if regexSakeHost.MatchString(r.Host) {
		// Redirect to the sake server
		sake.HandleRequest(w, r)
		return
	}

	// Check for *.gamestats(2).gs.* or gamestats(2).gs.*
	if regexGamestatsHost.MatchString(r.Host) {
		// Redirect to the gamestats server
		gamestats.HandleWebRequest(w, r)
		return
	}

	// Check for *.race.gs.* or race.gs.*
	if regexRaceHost.MatchString(r.Host) {
		// Redirect to the race server
		race.HandleRequest(w, r)
		return
	}

	moduleName := "NAS:" + r.RemoteAddr

	// Handle conntest server
	if strings.HasPrefix(r.Host, "conntest.") {
		handleConnectionTest(w)
		return
	}

	// Handle DWC auth requests
	if r.URL.String() == "/ac" || r.URL.String() == "/pr" || r.URL.String() == "/download" {
		handleAuthRequest(moduleName, w, r)
		return
	}

	// Handle /nastest.jsp
	if r.URL.Path == "/nastest.jsp" {
		handleNASTest(w)
		return
	}

	// Check for /payload
	if strings.HasPrefix(r.URL.String(), "/payload") {
		logging.Info("NAS", aurora.Yellow(r.Method), aurora.Cyan(r.URL), "via", aurora.Cyan(r.Host), "from", aurora.BrightCyan(r.RemoteAddr))
		if payloadServerAddress != "" {
			// Forward the request to the payload server
			forwardPayloadRequest(moduleName, w, r)
		} else {
			handlePayloadRequest(moduleName, w, r)
		}
		return
	}

	// Stage 1
	if match := regexStage1URL.FindStringSubmatch(r.URL.String()); match != nil {
		val, err := strconv.Atoi(match[1])
		if err != nil {
			panic(err)
		}

		logging.Info("NAS", "Get stage 1:", aurora.Yellow(r.Method), aurora.Cyan(r.URL), "via", aurora.Cyan(r.Host), "from", aurora.BrightCyan(r.RemoteAddr))
		downloadStage1(w, val)
		return
	}

	// Check for /api/groups
	if r.URL.Path == "/api/groups" {
		api.HandleGroups(w, r)
		return
	}

	// Check for /api/json
	if r.URL.Path == "/api/json" || r.URL.Path == "/json" {
		api.HandleJson(w, r)
		return
	}

	//HandleGPCMFetch
	// Check for HandleGPCMFetch
	if r.URL.Path == "/api/jsonADMIN" || r.URL.Path == "/jsonADMIN" {
		api.HandleGPCMFetch(w, r)
		return
	}

	// Check for /api/stats
	if r.URL.Path == "/api/stats" {
		api.HandleStats(w, r)
		return
	}

	// Check for /api/ban
	if r.URL.Path == "/api/ban" {
		api.HandleBan(w, r)
		return
	}

	if r.URL.Path == "/api/delban" {
		api.HandleBanDel(w, r)
		return
	}

	if r.URL.Path == "/api/delunban" {
		api.HandleUnBanDel(w, r)
		return
	}

	// Check for /api/unban
	if r.URL.Path == "/api/unban" {
		api.HandleUnban(w, r)
		return
	}

	// Check for /api/kick
	if r.URL.Path == "/api/kick" {
		api.HandleKick(w, r)
		return
	}

	if r.URL.Path == "/api/vpnwhitelist" {
		api.HandleVPNFetch(w, r)
		return
	}

	if r.URL.Path == "/api/csnum" {
		api.HandlecsnumFetch(w, r)
		return
	}

	if r.URL.Path == "/api/trusted" {
		api.HandleFetch(w, r)
		return
	}

	if r.URL.Path == "/api/test" {
		api.HandleTest(w, r)
		return
	}

	if r.URL.Path == "/tt" {
		api.HandleTimeTrials(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/") {
		filePath := filepath.Join("./www", filepath.Clean(r.URL.Path))
		oripath := filePath

		// Set CORS headers to allow all origins
		w.Header().Set("Access-Control-Allow-Origin", "*") //mainly for rooms_mapping.txt
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		// **Force correct MIME type**
		//something about APPLE
		if strings.HasSuffix(filePath, ".ipa") {
			w.Header().Set("Content-Type", "application/octet-stream")
		} else if strings.HasSuffix(filePath, ".plist") {
			w.Header().Set("Content-Type", "text/xml")
		} else if strings.HasSuffix(filePath, "md5.min.js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		// else {
		//	// Use default behavior for other file types
		//	w.Header().Set("Content-Type", http.DetectContentType([]byte(filePath)))
		//}

		// Checking if the requested file exists
		if _, err := os.Stat(filePath); err != nil {
			// If os.Stat returns an error, log the error or handle it as needed
			//fmt.Println("File not found:", err)

			// Try appending "/index.html" to the file path
			indexPath := filepath.Join(filePath, "/index.html")
			if _, err := os.Stat(indexPath); err != nil {
				// If appending "/index.html" also doesn't work, return a 404 response
				fmt.Println("File not found:", oripath)
				replyHTTPError(w, 404, "404 Not Found")
				//err := errors.New("This is a forced error")
				//fmt.Println("Error:", err.Error())
				return
			}

			// Serve the index file if it exists
			http.ServeFile(w, r, indexPath)
			return
		}

		// Serve the file if it exists
		http.ServeFile(w, r, filePath)
		return
	}

	logging.Info("NAS", aurora.Yellow(r.Method), aurora.Cyan(r.URL), "via", aurora.Cyan(r.Host), "from", aurora.BrightCyan(r.RemoteAddr))
	replyHTTPError(w, 404, "404 Not Found")
}

func replyHTTPError(w http.ResponseWriter, errorCode int, errorString string) {
	response := "<html>\n" +
		"<head><title>" + errorString + "</title></head>\n" +
		"<body>\n" +
		"<center><h1>" + errorString + "</h1></center>\n" +
		"<hr><center>" + serverName + "</center>\n" +
		"</body>\n" +
		"</html>\n"

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Header().Set("Connection", "close")
	w.Header().Set("Server", "Nintendo")
	w.WriteHeader(errorCode)
	w.Write([]byte(response))
}

func handleNASTest(w http.ResponseWriter) {
	response := "" +
		"<html>\n" +
		"<body>\n" +
		"</br>AuthServer is up</br> \n" +
		"\n" +
		"</body>\n" +
		"</html>\n"

	w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Header().Set("Connection", "close")
	w.Header().Set("NODE", "authserver-service.authserver.svc.cluster.local")
	w.Header().Set("Server", "Nintendo")

	w.WriteHeader(200)
	w.Write([]byte(response))
}

func forwardPayloadRequest(moduleName string, w http.ResponseWriter, r *http.Request) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	r.URL.Scheme = "http"
	r.URL.Host = payloadServerAddress
	r.RequestURI = ""
	r.Host = payloadServerAddress

	resp, err := client.Do(r)
	if err != nil {
		logging.Error(moduleName, "Error forwarding payload request:", err)
		replyHTTPError(w, http.StatusBadGateway, "502 Bad Gateway")
		return
	}
	defer resp.Body.Close()

	// Copy the response headers and status code
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Error(moduleName, "Error reading response body:", err)
		replyHTTPError(w, http.StatusInternalServerError, "500 Internal Server Error")
		return
	}
	w.Write(body)
}
