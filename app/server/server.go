package server

import (
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"go-whios/app/store"
	"log"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/likexian/whois"
	"go.etcd.io/bbolt"
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
	Store          store.Store
}

var (
	mu sync.Mutex
)

var db *bbolt.DB

func (s Server) Run(ctx context.Context) error {
	log.Printf("[INFO] activate rest server")
	log.Printf("[INFO] Listen: %s", s.Listen)
	r := mux.NewRouter()
	//add static folder
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	r.HandleFunc("/", s.serveIndex).Methods("GET")
	r.HandleFunc("/check", s.checkDomain).Methods("POST")
	r.HandleFunc("/delete", s.deleteDomain).Methods("POST")
	r.HandleFunc("/domains", s.listDomains).Methods("GET")

	r.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		render.PlainText(w, r, "User-agent: *\nDisallow: /\n")
	})

	log.Printf("[INFO] Running server on %s", s.Listen)

	go func() {
		<-ctx.Done()
		if err := db.Close(); err != nil {
			log.Printf("[ERROR] failed to close db, %v", err)
		}
	}()

	if err := http.ListenAndServe(s.Listen, r); err != nil {
		log.Printf("[ERROR] failed, %+v", err)
	}
	return nil
}

func (s Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

func (s Server) listDomains(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	domains := LoadDomainsFromDB(s.Store)

	for _, domain := range domains {
		renderTableRow(w, domain)
	}
}

func LoadDomainsFromDB(stor store.Store) map[string]store.DomainInfo {
	return stor.LoadDomainsFromDB()
}

// checkDomain перевіряє WHOIS та SSL домену
func (s Server) checkDomain(w http.ResponseWriter, r *http.Request) {
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
	info := store.DomainInfo{
		Uuid:         uuid,
		Domain:       domain,
		WhoisData:    whoisData,
		SSLValid:     sslValid,
		SSLExpires:   sslExpires,
		DomainExpire: domainExpire,
		IsExpired:    isExpired,
	}

	s.Store.SaveDomain(info)

	renderTableRow(w, info)
}

func (s Server) deleteDomain(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	domain := r.Form.Get("domain")

	mu.Lock()
	defer mu.Unlock()

	s.Store.DeleteDomain(domain)

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

func renderTableRow(w http.ResponseWriter, domain store.DomainInfo) {
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
