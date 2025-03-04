package server

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
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
	DB             *bbolt.DB
}

var (
	domains = make(map[string]DomainInfo)
	mu      sync.Mutex
)

var db *bbolt.DB

func (s Server) Run(ctx context.Context) error {
	log.Printf("[INFO] activate rest server")
	log.Printf("[INFO] Listen: %s", s.Listen)
	r := mux.NewRouter()
	//add static folder
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	r.HandleFunc("/", serveIndex).Methods("GET")
	r.HandleFunc("/check", checkDomain).Methods("POST")
	r.HandleFunc("/delete", deleteDomain).Methods("POST")
	r.HandleFunc("/domains", listDomains).Methods("GET")

	r.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		render.PlainText(w, r, "User-agent: *\nDisallow: /\n")
	})

	log.Printf("[INFO] Running server on %s", s.Listen)

	if err := http.ListenAndServe(s.Listen, r); err != nil {
		log.Printf("[ERROR] failed, %+v", err)
	}
	return nil
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

func listDomains(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	domains := LoadDomainsFromDB()

	for _, domain := range domains {
		renderTableRow(w, domain)
	}
}

func LoadDomainsFromDB() map[string]DomainInfo {
	db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("domains"))
		b.ForEach(func(k, v []byte) error {
			var domain DomainInfo
			json.Unmarshal(v, &domain)
			domains[string(k)] = domain
			return nil
		})
		return nil
	})

	return domains
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
	//SaveDomain(info)

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

func SaveDomain(domain DomainInfo) {
	db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("domains"))
		data, _ := json.Marshal(domain)
		return b.Put([]byte(domain.Domain), data)
	})
}

func DeleteDomain(domain string) {
	db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("domains"))
		return b.Delete([]byte(domain))
	})
}
