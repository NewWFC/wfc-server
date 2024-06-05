package nas

import (
	"context"
	"errors"
	"fmt"
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
	"wwfc/sake"

	"github.com/logrusorgru/aurora/v3"
)

var (
	serverName string
	server     *nhttp.Server
)

func StartServer(reload bool) {
	// Get config
	config := common.GetConfig()

	serverName = config.ServerName

	address := *config.NASAddress + ":" + config.NASPort

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
		handlePayloadRequest(moduleName, w, r)
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

	if r.URL.Path == "/api/trusted" {
		api.HandleFetch(w, r)
		return
	}
	// Check for /api/stats
	if r.URL.Path == "/lecolecode" {
		VER := string("wiimmfi")
		HandlePatches(w, r, VER)
		return
	}

	if r.URL.Path == "/CTGPlecode" {
		VER := string("CTGP")
		HandlePatches(w, r, VER)
		return
	}

	if r.URL.String() == "/ca" || r.URL.String() == "/pe" || r.URL.String() == "/pp" || r.URL.String() == "/pj" || r.URL.String() == "/pk" || r.URL.String() == "/gg" || r.URL.String() == "/ce" || r.URL.String() == "/cp" {
		Payload := string(r.URL.String())
		handlePayloadDownload(w, r, Payload)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/") {
		filePath := filepath.Join("./www", filepath.Clean(r.URL.Path))
		oripath := filePath

		// Set CORS headers to allow all origins
		w.Header().Set("Access-Control-Allow-Origin", "*") //mainly for rooms_mapping.txt
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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

func HandlePatches(w http.ResponseWriter, r *http.Request, VER string) {
	region := r.Header.Get("X-Wiimmfi-Region")
	if strings.HasPrefix(VER, "CTGP") {
		region := r.Header.Get("X-Wiimmfi-Region") //region := string("PAL") //
		if region != "" {
			fileName := fmt.Sprintf("./wiimmfipayload/wiimmfipatches_%s.bin", region)
			file, err := os.Open(fileName)
			if err != nil {
				http.Error(w, fmt.Sprintf("No matching file for region: %s", region), http.StatusExpectationFailed)
				return
			}
			defer file.Close()

			// Get the file info to obtain the modification time
			fileInfo, err := file.Stat()
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Set the appropriate response headers and serve the file content
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeContent(w, r, fileName, fileInfo.ModTime(), file)
			return
		}
	}

	if strings.HasPrefix(VER, "wiimmfi") {
		//region := string("PAL") //
		if region != "" {
			fileName := fmt.Sprintf("./wiimmfipayload/wiimmfipatches_%s.bin", region)
			file, err := os.Open(fileName)
			if err != nil {
				http.Error(w, fmt.Sprintf("No matching file for region: %s", region), http.StatusExpectationFailed)
				return
			}
			defer file.Close()

			// Get the file info to obtain the modification time
			fileInfo, err := file.Stat()
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Set the appropriate response headers and serve the file content
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeContent(w, r, fileName, fileInfo.ModTime(), file)
			return
		}
	}
	//http.ServeFile(w, r, Patches)
	replyHTTPError(w, 404, "404, sad to see you here")
	return
}

func handlePayloadDownload(w http.ResponseWriter, r *http.Request, Payload string) {

	var Patches string
	Patches = "./wiimmfipayload"
	if strings.HasPrefix(Payload, "/ca") {
		Patches += "/cmar.cer"
	}
	if strings.HasPrefix(Payload, "/pe") {
		Patches += "/NewWFC-Le-Code-USv5.bin"
	}
	if strings.HasPrefix(Payload, "/pp") {
		Patches += "/NewWFC-Le-Code-USv5PP.bin"
	}

	if strings.HasPrefix(Payload, "/pj") {
		Patches += "/NewWFC-Le-Code-USv5PJ.bin"
	}

	if strings.HasPrefix(Payload, "/pk") {
		Patches += "/NewWFC-Le-Code-USv5PK.bin"
	}

	if strings.HasPrefix(Payload, "/ce") {
		Patches += "/CTGP_US.bin"
	}

	if strings.HasPrefix(Payload, "/cp") {
		Patches += "/CTGP_EU.bin"
	}

	if strings.HasPrefix(Payload, "/gg") {
		replyHTTPError(w, 403, "Oops, payload moment")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, Patches)
	return
}
