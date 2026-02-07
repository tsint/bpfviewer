// Copyright 2026 tsint
//
// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	defaultListenAddr = ":8086"
)

var (
	bpfDir  = "bpf"
	htmlDir = "html"
)

var (
	hostURL     string
	listenAddr  string
	daemonMode  bool
	showVersion bool
	version     = "v0.1"
)

func main() {

	var fileName string
	var tempFile string
	flag.StringVarP(&fileName, "file", "f", "", "BPF object file")
	flag.StringVarP(&tempFile, "temp", "t", "bpf_template.html", "the template for output HTML file")
	flag.StringVar(&hostURL, "host", "", "Home page URL (for back button)")
	flag.StringVar(&listenAddr, "listen", defaultListenAddr, "Listen address for daemon mode")
	flag.BoolVar(&daemonMode, "daemon", false, "Run in daemon mode (HTTP server)")
	flag.BoolVar(&showVersion, "version", false, "Show version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("bpfviewer version %s\n", version)
		return
	}

	// Daemon mode
	if daemonMode {
		runDaemonMode()
		return
	}

	// Normal mode: generate single HTML file
	if fileName == "" {
		log.Fatal("Please specify a BPF object file")
	}

	res := parseFile(fileName)

	// Set HomeURL if host is provided
	if hostURL != "" {
		res["HomeURL"] = hostURL
	}

	tmpl, err := template.ParseFiles(tempFile)
	if err != nil {
		log.Println("Error parsing template:", err)
		return
	}

	name := strings.ToLower(fileName)
	ext := filepath.Ext(name)
	nameWithoutSuffix := strings.TrimSuffix(name, ext)

	// 打开输出文件
	outFile := nameWithoutSuffix + ".html"
	file, err := os.Create(outFile)
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, res)
	if err != nil {
		log.Fatalf("Error executing template: %v", err)
	}

}

func TitleFromFileName(fileName string) string {
	fileName = strings.ToLower(fileName)
	ext := filepath.Ext(fileName)
	fileName = strings.TrimSuffix(fileName, ext)

	if len(fileName) < 16 {
		return fileName
	}

	// For other files, just truncate
	return "..." + fileName[len(fileName)-16:]
}

func isJump(ins asm.Instruction) bool {
	op := ins.OpCode
	jop := op.JumpOp()
	if jop == asm.InvalidJumpOp {
		return false
	}
	if jop != asm.Call {
		return true
	}
	return false
}

func isMapFunc(f asm.BuiltinFunc) bool {
	switch f {
	case asm.FnMapLookupElem, asm.FnMapUpdateElem, asm.FnMapDeleteElem,
		asm.FnMapPushElem, asm.FnMapPopElem, asm.FnMapPeekElem, asm.FnMapLookupPercpuElem,
		asm.FnRingbufOutput, asm.FnRingbufReserve, asm.FnPerfEventOutput, asm.FnRingbufQuery,
		asm.FnForEachMapElem, asm.FnTailCall, asm.FnRedirectMap, asm.FnSkRedirectMap,
		asm.FnTracePrintk:
		return true
	default:
		return false
	}
}

func parseBPF(fileName string, reader *bytes.Reader, results map[string]string) {
	var codeBuilder strings.Builder
	codeBuilder.WriteString("// File: ")
	codeBuilder.WriteString(fileName)
	codeBuilder.WriteString("\n\n")

	var graphBuilder strings.Builder
	graphBuilder.WriteString("flowchart LR\n")

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		log.Errorf("failed to load collection spec: %v", err)
		return
	}

	var mapsList []*ebpf.MapSpec
	mapNode := []string{}
	for _, m := range spec.Maps {
		mapsList = append(mapsList, m)
		mapNode = append(mapNode, m.Name)
	}
	sort.Slice(mapsList, func(i, j int) bool {
		return mapsList[i].Name < mapsList[j].Name
	})

	var progsList []*ebpf.ProgramSpec
	for _, p := range spec.Programs {
		progsList = append(progsList, p)
	}
	sort.Slice(progsList, func(i, j int) bool {
		return progsList[i].Name < progsList[j].Name
	})

	for _, m := range mapsList {
		codeBuilder.WriteString(fmt.Sprintf("struct {\n    __uint(type, %s);\n    __uint(max_entries, %d);"+
			"\n    __uint(key_size, %d);\n    __uint(value_size, %d);\n} %s SEC(\".maps\");\n\n",
			m.Type.String(), m.MaxEntries, m.KeySize, m.ValueSize, m.Name))

		graphBuilder.WriteString(m.Name)
		graphBuilder.WriteString("[(\"")
		graphBuilder.WriteString(m.Name)
		graphBuilder.WriteString("\")]\n")
	}

	for _, prog := range progsList {
		codeBuilder.WriteString(fmt.Sprintf("// SEC(\"%s\")\n// %s %s\n",
			prog.SectionName, prog.Type.String(), prog.Name))

		FormatInstructions(&codeBuilder, prog.Instructions)

		references := make(map[string]bool)
		previousRef := map[asm.Register][]string{}
		isSet := false
		for _, ins := range prog.Instructions {
			if ins.IsBuiltinCall() {
				builtinFunc := asm.BuiltinFunc(ins.Constant)
				if !isMapFunc(builtinFunc) {
					continue
				}
				builtinFuncName := fmt.Sprint(builtinFunc)
				ref := []string{}
				if strings.HasPrefix(builtinFuncName, "FnMap") &&
					strings.HasSuffix(builtinFuncName, "Elem") {
					builtinFuncName = strings.TrimPrefix(builtinFuncName, "FnMap")
					builtinFuncName = strings.TrimSuffix(builtinFuncName, "Elem")
					ref, _ = previousRef[asm.R1]
				} else if builtinFunc == asm.FnPerfEventOutput ||
					builtinFunc == asm.FnRingbufOutput ||
					builtinFunc == asm.FnRingbufReserve {
					if builtinFunc == asm.FnPerfEventOutput {
						builtinFuncName = "PerfEventOutput"
						ref, _ = previousRef[asm.R2]
					} else {
						builtinFuncName = "RingbufOutput"
						ref, _ = previousRef[asm.R1]
					}
				} else if builtinFunc == asm.FnRingbufQuery || builtinFunc == asm.FnForEachMapElem || builtinFunc == asm.FnTailCall {
					builtinFuncName = strings.TrimPrefix(builtinFuncName, "Fn")
					if builtinFunc == asm.FnTailCall {
						ref, _ = previousRef[asm.R2]
					} else {
						ref, _ = previousRef[asm.R1]
					}
				}
				if len(ref) > 0 {
					for _, r := range ref {
						if r != "" {
							references[r+"|"+builtinFuncName] = true
						}
					}
				}
				isSet = false
				previousRef = map[asm.Register][]string{}
			}
			if isJump(ins) {
				isSet = false
				continue
			}
			if ref := ins.Reference(); ref != "" {
				if !isSet {
					previousRef[ins.Dst] = append(previousRef[ins.Dst], ref)
					isSet = true
				}
			}
		}
		possibleVerbs := []string{
			"Lookup",
			"Push",
			"Pop",
			"Peek",
			"LookupPercpu",
			"Update",
			"Delete",
		}

		referencesList := []string{}
		for ref := range references {
			referencesList = append(referencesList, ref)
		}
		sort.Strings(referencesList)
		for _, ref := range referencesList {
			if !references[ref] {
				continue
			}
			parts := strings.SplitN(ref, "|", 2)
			fnName := parts[1]
			mapName := parts[0]
			// If several arrows exist, merge them
			verbs := []string{}
			if mapName == ".rodata" {
				fnName = "Lookup"
				if !references[".rodata|Lookup"] {
					continue
				}
				references[".rodata|Lookup"] = false
			} else {
				for _, verb := range possibleVerbs {
					if references[mapName+"|"+verb] {
						verbs = append(verbs, verb)
					}
				}
				if len(verbs) > 1 {
					for _, verb := range verbs {
						references[mapName+"|"+verb] = false
					}
					fnName = strings.Join(verbs, "+")
				}
			}

			graphBuilder.WriteString(prog.Name)
			graphBuilder.WriteString(" -- \"")
			graphBuilder.WriteString(fnName)
			graphBuilder.WriteString("\" --> ")
			graphBuilder.WriteString(mapName)
			graphBuilder.WriteString("\n")
		}
		graphBuilder.WriteString(prog.Name)
		graphBuilder.WriteString("[\"")
		graphBuilder.WriteString(prog.Name)
		graphBuilder.WriteString("\"]\n")
	}

	results["CodeTitle"] = "Source (" + TitleFromFileName(fileName) + ")"
	results["CodeContent"] = codeBuilder.String()
	results["GraphTitle"] = "Graph (" + TitleFromFileName(fileName) + ")"
	results["GraphContent"] = graphBuilder.String()
	results["GraphMapNodes"] = strings.Join(mapNode, ",")
}

func isElf(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// ELF magic: 0x7f 45 4c 46
	return data[0] == 0x7f && data[1] == 0x45 && data[2] == 0x4c && data[3] == 0x46
}

//export readFile
func parseFile(fileName string) map[string]string {
	results := make(map[string]string)

	data, err := os.ReadFile(fileName) // just pass the file name
	if err != nil {
		fmt.Print(err)
		return nil
	}

	if len(data) < 265 {
		log.Errorf("cannot parse file (%d bytes)", len(data))
		return nil
	}

	if isElf(data) {
		log.Infof("ELF file detected")
		parseBPF(fileName, bytes.NewReader(data), results)
	} else {
		log.Error("Cannot identify file. Please give either a tar file generated by 'ig image export' or an ELF file.")
		return nil
	}

	return results
}

// FileInfo represents information about a BPF file
type FileInfo struct {
	Name     string `json:"name"`
	HTMLName string `json:"htmlName"`
	Size     string `json:"size"`
	Modified string `json:"modified"`
}

// runDaemonMode starts the HTTP server in daemon mode
func runDaemonMode() {
	// Ensure directories exist
	ensureDirs()

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/api/files", handleFilesList)
	http.HandleFunc("/api/upload", handleUpload)
	http.HandleFunc("/api/generate", handleGenerate)
	http.HandleFunc("/api/files/", handleDeleteFile)
	http.HandleFunc("/html/", handleHTMLViewer)
	// http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(htmlDir))))

	// Build the base URL for the home button
	baseURL := fmt.Sprintf("http://%s", listenAddr)
	if strings.HasPrefix(listenAddr, "http://") {
		baseURL = listenAddr
	}

	log.Infof("Starting BPF Viewer server on %s", baseURL)
	log.Infof("BPF directory: %s", bpfDir)
	log.Infof("HTML directory: %s", htmlDir)
	log.Infof("Open %s in your browser", baseURL)

	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// ensureDirs creates necessary directories if they don't exist
func ensureDirs() {
	dirs := []string{bpfDir, htmlDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}
}

// handleHome serves the main page with file list
func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Read main template
	homeContent, err := os.ReadFile("home.html")
	if err != nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		log.Errorf("Failed to read home.html: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(homeContent))
}

// handleFilesList returns the list of BPF files
func handleFilesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	files, err := listBPFFiles()
	if err != nil {
		http.Error(w, "Failed to list files", http.StatusInternalServerError)
		log.Errorf("Failed to list BPF files: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

// handleUpload processes file uploads
func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit upload size to 200MB
	r.ParseMultipartForm(200 << 20)

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		log.Errorf("Failed to get file from form: %v", err)
		return
	}
	defer file.Close()

	// Check file extension
	name := strings.ToLower(handler.Filename)
	ext := filepath.Ext(name)
	nameWithoutSuffix := strings.TrimSuffix(name, ext)

	// Check if it's a valid ELF file
	buf := make([]byte, 265)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}
	if n < 4 {
		http.Error(w, "File too small to be a valid BPF file", http.StatusBadRequest)
		return
	}

	if !isElf(buf) {
		http.Error(w, "Invalid BPF file (not an ELF file)", http.StatusBadRequest)
		return
	}

	// Reset file pointer for copy
	if _, err := file.Seek(0, 0); err != nil {
		http.Error(w, "Failed to process file", http.StatusInternalServerError)
		return
	}

	// Handle duplicate filenames
	filename := nameWithoutSuffix
	destPath := filepath.Join(bpfDir, filename)

	// Check if file exists and handle duplicates
	if _, err := os.Stat(destPath); err == nil {
		// File exists, add date suffix and counter
		baseName := filename
		dateSuffix := time.Now().Format("20060102")
		counter := 1

		for {
			newFilename := fmt.Sprintf("%s_%s_%d", baseName, dateSuffix, counter)
			newPath := filepath.Join(bpfDir, newFilename)
			if _, err := os.Stat(newPath); os.IsNotExist(err) {
				filename = newFilename
				destPath = newPath
				break
			}
			counter++
		}
	}

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		log.Errorf("Failed to create file %s: %v", destPath, err)
		return
	}
	defer destFile.Close()

	// Copy file content
	if _, err := io.Copy(destFile, file); err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		log.Errorf("Failed to copy file content: %v", err)
		return
	}

	log.Infof("File uploaded successfully: %s", filename)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"filename": filename,
		"message":  "File uploaded successfully",
	})
}

// handleGenerate generates HTML for a BPF file
func handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Filename string `json:"filename"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Filename == "" {
		http.Error(w, "Filename is required", http.StatusBadRequest)
		return
	}

	// Check if BPF file exists
	bpfPath := filepath.Join(bpfDir, req.Filename)
	if _, err := os.Stat(bpfPath); os.IsNotExist(err) {
		http.Error(w, "BPF file not found", http.StatusNotFound)
		return
	}

	// Generate HTML filename
	htmlFilename := strings.TrimSuffix(req.Filename, filepath.Ext(req.Filename)) + ".html"
	htmlPath := filepath.Join(htmlDir, htmlFilename)

	// Build base URL
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = listenAddr
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, host)

	// Parse BPF file
	results := parseFile(bpfPath)
	if results == nil {
		http.Error(w, "Failed to parse BPF file", http.StatusInternalServerError)
		return
	}

	// Set HomeURL
	results["HomeURL"] = baseURL

	// Parse and execute template
	tmpl, err := template.ParseFiles("bpf_template.html")
	if err != nil {
		http.Error(w, "Failed to parse template", http.StatusInternalServerError)
		log.Errorf("Failed to parse template: %v", err)
		return
	}

	// Create HTML file
	outFile, err := os.Create(htmlPath)
	if err != nil {
		http.Error(w, "Failed to create HTML file", http.StatusInternalServerError)
		log.Errorf("Failed to create HTML file %s: %v", htmlPath, err)
		return
	}
	defer outFile.Close()

	if err := tmpl.Execute(outFile, results); err != nil {
		http.Error(w, "Failed to generate HTML", http.StatusInternalServerError)
		log.Errorf("Failed to execute template: %v", err)
		return
	}

	log.Infof("HTML generated successfully: %s", htmlFilename)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"htmlName": htmlFilename,
		"message":  "HTML generated successfully",
	})
}

// handleDeleteFile deletes a BPF file and its associated HTML
func handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract filename from URL path
	filename := strings.TrimPrefix(r.URL.Path, "/api/files/")
	if filename == "" {
		http.Error(w, "Filename is required", http.StatusBadRequest)
		return
	}

	// Delete BPF file
	bpfPath := filepath.Join(bpfDir, filename)
	if err := os.Remove(bpfPath); err != nil && !os.IsNotExist(err) {
		http.Error(w, "Failed to delete BPF file", http.StatusInternalServerError)
		log.Errorf("Failed to delete BPF file %s: %v", bpfPath, err)
		return
	}

	// Delete associated HTML file
	htmlFilename := strings.TrimSuffix(filename, filepath.Ext(filename)) + ".html"
	htmlPath := filepath.Join(htmlDir, htmlFilename)
	if err := os.Remove(htmlPath); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to delete HTML file %s: %v", htmlPath, err)
	}

	log.Infof("File deleted successfully: %s", filename)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "File deleted successfully",
	})
}

// handleHTMLViewer serves the generated HTML files
func handleHTMLViewer(w http.ResponseWriter, r *http.Request) {
	// Extract the HTML filename from the path
	htmlFilename := strings.TrimPrefix(r.URL.Path, "/html/")
	if htmlFilename == "" {
		http.NotFound(w, r)
		return
	}

	htmlPath := filepath.Join(htmlDir, htmlFilename)

	// Check if file exists
	if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
		http.NotFound(w, r)
		log.Warnf("HTML file not found: %s", htmlPath)
		return
	}

	// Serve the file
	http.ServeFile(w, r, htmlPath)
}

// listBPFFiles returns a list of BPF files in the bpf directory
func listBPFFiles() ([]FileInfo, error) {
	var files []FileInfo

	entries, err := os.ReadDir(bpfDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := strings.ToLower(entry.Name())
		ext := filepath.Ext(name)
		nameWithoutSuffix := strings.TrimSuffix(name, ext)

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Get file size
		size := formatSize(info.Size())

		// Get modified time
		modified := info.ModTime().Format("2006-01-02 15:04:05")

		// Generate HTML filename
		htmlName := nameWithoutSuffix + ".html"

		files = append(files, FileInfo{
			Name:     name,
			HTMLName: htmlName,
			Size:     size,
			Modified: modified,
		})
	}

	// Sort by name (descending)
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name > files[j].Name
	})

	return files, nil
}

// formatSize formats a file size in human-readable format
func formatSize(bytes int64) string {
	if bytes < 1024 {
		return strconv.FormatInt(bytes, 10) + " B"
	}
	units := []string{"KB", "MB", "GB"}
	size := float64(bytes) / 1024 // Convert to KB first
	unitIndex := 0

	for size >= 1024 && unitIndex < len(units)-1 {
		size /= 1024
		unitIndex++
	}

	return fmt.Sprintf("%.1f %s", size, units[unitIndex])
}
