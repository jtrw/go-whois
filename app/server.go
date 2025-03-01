package server

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth_chi"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/jtrw/go-rest"
	"github.com/likexian/whois"
	"github.com/pkg/errors"
)

type DomainInfo struct {
	Uuid         string
	Domain       string
	WhoisData    string
	SSLValid     bool
	SSLExpires   string
	DomainExpire string
	IsExpired    bool
}

type Server struct {
	Listen         string
	PinSize        int
	MaxPinAttempts int
	MaxExpire      time.Duration
	WebRoot        string
	WebFS          embed.FS
	Version        string
	AuthLogin      string
	AuthPassword   string
	Context        context.Context
}

func (s Server) Run(ctx context.Context) error {
	log.Printf("[INFO] activate rest server")
	log.Printf("[INFO] Listen: %s", s.Listen)

	httpServer := &http.Server{
		Addr:              s.Listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		if httpServer != nil {
			if clsErr := httpServer.Close(); clsErr != nil {
				log.Printf("[ERROR] failed to close proxy http server, %v", clsErr)
			}
		}
	}()

	err := httpServer.ListenAndServe()
	log.Printf("[WARN] http server terminated, %s", err)

	if err != http.ErrServerClosed {
		return errors.Wrap(err, "server failed")
	}
	return err
}

func (s Server) routes() chi.Router {
	router := chi.NewRouter()
	router.Use(middleware.RequestID, middleware.RealIP)
	router.Use(middleware.Throttle(1000), middleware.Timeout(60*time.Second))
	router.Use(rest.AppInfo("Whios", "Jrtw", s.Version), rest.Ping)
	router.Use(tollbooth_chi.LimitHandler(tollbooth.NewLimiter(10, nil)))
	router.Use(middleware.Logger)

	router.Route(
		"/api/v1", func(r chi.Router) {
			//r.Use(Cors)
			//r.Use(Auth(authHandle.GetToken()))

			r.HandleFunc("/index", serveIndex).Methods("GET")
			r.Post("/check", checkDomain)
			r.Post("/delete", deleteDomain)
			r.Get("/domains", listDomains)
		},
	)

	router.Get(
		"/robots.txt", func(w http.ResponseWriter, r *http.Request) {
			render.PlainText(w, r, "User-agent: *\nDisallow: /\n")
		},
	)

	addFileServer(router, s.WebFS, s.WebRoot, s.Version)

	return router
}

func addFileServer(r chi.Router, embedFS embed.FS, webRoot, version string) {
	var webFS http.Handler
	log.Printf("[INFO] webRoot: %s", webRoot)
	if _, err := os.Stat(webRoot); err == nil {
		log.Printf("[INFO] run file server from %s from the disk", webRoot)
		webFS = http.FileServer(http.Dir(webRoot))
	} else {
		log.Printf("[INFO] run file server, embedded")
		var contentFS, _ = fs.Sub(embedFS, "web")
		webFS = http.FileServer(http.FS(contentFS))
	}

	webFS = http.StripPrefix("/web", webFS)
	r.Get("/web", http.RedirectHandler("/web/", http.StatusMovedPermanently).ServeHTTP)

	r.With(tollbooth_chi.LimitHandler(tollbooth.NewLimiter(20, nil)),
		middleware.Timeout(10*time.Second),
		cacheControl(time.Hour, version),
	).Get("/web/*", func(w http.ResponseWriter, r *http.Request) {
		// don't show dirs, just serve files
		if strings.HasSuffix(r.URL.Path, "/") && len(r.URL.Path) > 1 && r.URL.Path != ("/web/") {
			http.NotFound(w, r)
			return
		}
		webFS.ServeHTTP(w, r)
	})
}

func cacheControl(expiration time.Duration, version string) func(http.Handler) http.Handler {
	etag := func(r *http.Request, version string) string {
		s := version + ":" + r.URL.String()
		return fmt.Sprintf("%x", md5.Sum([]byte(s)))
	}

	return func(h http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			e := `"` + etag(r, version) + `"`
			w.Header().Set("Etag", e)
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, no-cache", int(expiration.Seconds())))

			if match := r.Header.Get("If-None-Match"); match != "" {
				if strings.Contains(match, e) {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
			h.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

func listDomains(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	for _, domain := range domains {
		renderTableRow(w, domain)
	}
}

// checkDomain перевіряє WHOIS та SSL домену
func checkDomain(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	domain := r.Form.Get("domain")

	mu.Lock()
	defer mu.Unlock()

	// Отримуємо WHOIS-дані
	whoisData, err := whois.Whois(domain)
	if err != nil {
		whoisData = fmt.Sprintf("Помилка отримання WHOIS: %v", err)
	}

	// Отримуємо дату закінчення домену
	domainExpire := extractExpirationDate(whoisData)

	// Перевіряємо SSL-сертифікат
	sslValid, sslExpires, err := checkSSLCertificate(domain)
	if err != nil {
		sslValid = false
		sslExpires = "Помилка"
	}

	isExpired := !sslValid

	uuid := uuid.New().String()
	info := DomainInfo{
		Uuid:         uuid,
		Domain:       domain,
		WhoisData:    whoisData,
		SSLValid:     sslValid,
		SSLExpires:   sslExpires,
		DomainExpire: domainExpire,
		IsExpired:    isExpired,
	}

	// Зберігаємо в БД
	SaveDomain(info)

	domains[domain] = info
	renderTableRow(w, info)
}

// deleteDomain видаляє домен
func deleteDomain(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	domain := r.Form.Get("domain")

	mu.Lock()
	defer mu.Unlock()

	// Видаляємо домен із пам’яті та бази
	DeleteDomain(domain)
	delete(domains, domain)

	// Повертаємо пусту відповідь для HTMX
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}

// extractExpirationDate шукає дату закінчення домену в WHOIS-даних
func extractExpirationDate(whoisData string) string {
	lines := strings.Split(whoisData, "\n")

	for _, line := range lines {
		log.Println(line)
		if strings.Contains(strings.ToLower(line), "expiry date") || strings.Contains(strings.ToLower(line), "renewal") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "Невідомо"
}

// checkSSLCertificate перевіряє SSL-сертифікат
func checkSSLCertificate(domain string) (bool, string, error) {
	conn, err := tls.Dial("tcp", domain+":443", nil)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false, "", fmt.Errorf("сертифікат не знайдено")
	}

	cert := certs[0]
	isValid := time.Now().Before(cert.NotAfter)
	return isValid, cert.NotAfter.Format("2006-01-02"), nil
}

// renderTableRow відображає HTML-рядок для таблиці
func renderTableRow(w http.ResponseWriter, domain DomainInfo) {
	// Замінюємо крапки у домені, бо HTMX не може працювати з "." у id
	// safeDomainID := strings.ReplaceAll(domain.Domain, ".", "-")
	// domain.Domain = safeDomainID

	tmpl := `
<tr id="row-{{.Uuid}}" class="{{if .IsExpired}}table-danger{{end}}">
    <td>{{.Domain}}</td>
    <td>{{.DomainExpire}}</td>
    <td>{{.SSLExpires}}</td>
    <td>
        <button class="btn btn-sm btn-danger"
                hx-post="/delete"
                hx-vals='{"domain": "{{.Domain}}"}'
                hx-target="#row-{{.Uuid}}"
                hx-swap="outerHTML">
            ❌ Видалити
        </button>
    </td>
</tr>`
	t := template.Must(template.New("row").Parse(tmpl))
	t.Execute(w, domain)
}
