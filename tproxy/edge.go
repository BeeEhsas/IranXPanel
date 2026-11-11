// IranXPanel WEB-proxy L7 edge — the container's public front for tproxy-server.
//
// Why this exists (replaces the previous socat L4 pipe): the relay is pinned
// upstream and requires, on every authenticated request, BOTH
//   * r.Host == config.PublicHostname exactly (README: "The relay must receive
//     the original Host"), and
//   * exactly ONE parsable address in X-Forwarded-For ("rejects a request that
//     carries a list or an unparsable value").
// PaaS edges break both assumptions. Railway's HTTP edge does not deliver the
// canonical public hostname as Host (verified live 2026-11: a bridge request
// carrying the correct capability reached the relay's internal path and died on
// the Host check while the very same capability is derived from that hostname —
// so the relay's config was right and the edge's Host was not), and it
// appends the real client IP to any client-supplied X-Forwarded-For, which
// carriers in Iran routinely inject, turning one address into a list. Render
// behaves differently but is not guaranteed either.
//
// This edge therefore rewrites, per request:
//   Host             -> $TGP_PUBLIC_HOSTNAME (the canonical hostname the link
//                       and the relay config both use);
//   X-Forwarded-For  -> the LAST parsable address of the inbound XFF chain
//                       (the address the platform edge itself observed — its
//                       overwrite-or-append is authoritative; anything a
//                       client injected earlier is dropped), falling back to
//                       the connection peer when no XFF address parses.
// Everything else passes through untouched, including WebSocket upgrades
// (the relay's default "websocket" carrier) and streaming long-poll bodies.
//
// Layout: platform edge :443 -> container 0.0.0.0:$PORT (this binary)
//                           -> 127.0.0.1:$TGP_RELAY_PORT tproxy-server
//                           -> 127.0.0.1:2398 mtproto-proxy
package main

import (
        "log"
        "net"
        "net/http"
        "net/http/httputil"
        "net/url"
        "os"
        "strings"
        "time"
)

func envRequired(name string) string {
        value := strings.TrimSpace(os.Getenv(name))
        if value == "" {
                log.Fatalf("edge: %s is required", name)
        }
        return value
}

// lastForwardedIP picks exactly one address for the relay's capacity
// accounting: the last parsable XFF entry (closest to the platform edge),
// otherwise the immediate connection peer.
func lastForwardedIP(r *http.Request) string {
        fields := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
        for i := len(fields) - 1; i >= 0; i-- {
                candidate := strings.TrimSpace(fields[i])
                if candidate != "" && net.ParseIP(candidate) != nil {
                        return candidate
                }
        }
        host, _, err := net.SplitHostPort(r.RemoteAddr)
        if err != nil {
                return r.RemoteAddr
        }
        return host
}

func main() {
        log.SetFlags(log.LstdFlags | log.LUTC)
        canonical := strings.ToLower(envRequired("TGP_PUBLIC_HOSTNAME"))
        listenPort := envRequired("PORT")
        relayPort := strings.TrimSpace(os.Getenv("TGP_RELAY_PORT"))
        if relayPort == "" {
                relayPort = "8082"
        }

        target, err := url.Parse("http://127.0.0.1:" + relayPort)
        if err != nil {
                log.Fatalf("edge: bad relay port %q: %v", relayPort, err)
        }

        transport := &http.Transport{
                Proxy:                 nil, // loopback hop — never consult proxy env vars
                MaxIdleConns:          256,
                MaxIdleConnsPerHost:   256,
                IdleConnTimeout:       90 * time.Second,
                ResponseHeaderTimeout: 0, // the relay parks downlink polls for up to 25s
        }

        proxy := &httputil.ReverseProxy{
                Rewrite: func(pr *httputil.ProxyRequest) {
                        // Route to the relay (Rewrite mode keeps the inbound URL otherwise).
                        pr.SetURL(target)
                        // The relay compares r.Host to its configured public hostname and
                        // 404s the whole authenticated surface on any mismatch. Out.Host
                        // starts as a clone of the inbound (PaaS-edge-rewritten) Host.
                        pr.Out.Host = canonical
                        // Exactly one address, always. The relay rejects a list.
                        pr.Out.Header.Set("X-Forwarded-For", lastForwardedIP(pr.In))
                },
                Transport: transport,
                ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
                        log.Printf("edge: relay error on %s %s: %v", r.Method, r.URL.Path, err)
                        w.Header().Set("Cache-Control", "no-store")
                        http.Error(w, "backend unavailable", http.StatusServiceUnavailable)
                },
        }

        server := &http.Server{
                Addr:              "0.0.0.0:" + listenPort,
                Handler:           proxy,
                ReadHeaderTimeout: 10 * time.Second,
        }

        server.SetKeepAlivesEnabled(true)
        log.Printf("edge: 0.0.0.0:%s -> 127.0.0.1:%s (host rewrite -> %s, xff normalized)",
                listenPort, relayPort, canonical)
        log.Fatal(server.ListenAndServe())
}
