// parcel-api is the test image's Unix-only HTTP service and in-container client.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const socket = "/tmp/parcel.sock"
const dataDir = "/state/data"

type Record struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

func recordPath(id string) (string, error) {
	if id != "before-candidate" && id != "during-staging" {
		return "", errors.New("unknown record")
	}
	return filepath.Join(dataDir, id+".json"), nil
}

func insert(r Record) error {
	dest, err := recordPath(r.ID)
	if err != nil || r.Value == "" || len(r.Value) > 128 {
		return errors.New("invalid record")
	}
	tmp, err := os.CreateTemp(dataDir, ".new-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = json.NewEncoder(tmp).Encode(r); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(tmp.Name(), dest); err != nil {
		return err
	}
	dir, err := os.Open(dataDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func serve() error {
	id := os.Getenv("RG_INSTANCE")
	if len(id) != 36 {
		return errors.New("missing instance identity")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	out, err := exec.Command("/parcel-note").Output()
	if err != nil {
		return err
	}
	var base struct{ Service, Edition string }
	if err = json.Unmarshal(out, &base); err != nil || base.Service != "parcel-note" ||
		(base.Edition != "blue" && base.Edition != "green") {
		return errors.New("invalid base service")
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	handler := func(w http.ResponseWriter, req *http.Request) {
		body := map[string]any{"instance": id, "hostname": hostname, "edition": base.Edition}
		status := http.StatusNotFound
		switch {
		case req.Method == "GET" && req.URL.Path == "/ready":
			ready := os.Getenv("RG_HEALTH") == "ready"
			body["ready"] = ready
			status = 503
			if ready {
				status = 200
			}
		case req.Method == "POST" && req.URL.Path == "/records":
			var r Record
			if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 1024)).Decode(&r); err != nil {
				status = 400
			} else if err := insert(r); err != nil {
				status = 500
			} else {
				status = 201
				body["record"] = r
			}
		case req.Method == "GET" && strings.HasPrefix(req.URL.Path, "/records/"):
			file, err := recordPath(strings.TrimPrefix(req.URL.Path, "/records/"))
			if err == nil {
				raw, err := os.ReadFile(file)
				var r Record
				if err == nil && json.Unmarshal(raw, &r) == nil {
					status = 200
					body["record"] = r
				} else if !os.IsNotExist(err) {
					status = 500
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	server := http.Server{Handler: http.HandlerFunc(handler), ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, MaxHeaderBytes: 4096}
	return server.Serve(listener)
}

func request(args []string) error {
	if len(args) != 3 {
		return errors.New("request requires method, local path and body")
	}
	method, path, body := args[0], args[1], args[2]
	if (method != "GET" && method != "POST") || (path != "/ready" && path != "/records" && !strings.HasPrefix(path, "/records/")) {
		return errors.New("invalid local request")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	client := http.Client{Transport: transport, Timeout: 750 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest(method, "http://parcel"+path, bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var value map[string]any
	if err = json.NewDecoder(io.LimitReader(res.Body, 8192)).Decode(&value); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": res.StatusCode, "body": value})
}

func main() {
	var err error
	if len(os.Args) == 1 {
		err = serve()
	} else if os.Args[1] == "request" {
		err = request(os.Args[2:])
	} else {
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
