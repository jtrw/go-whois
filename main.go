package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/likexian/whois"
	"go.etcd.io/bbolt"
)

// DomainInfo структура для збереження інформації про домен
type DomainInfo struct {
	Domain       string
	WhoisData    string
	SSLValid     bool
	SSLExpires   string
	DomainExpire string
	IsExpired    bool
}

var (
	domains = make(map[string]DomainInfo)
	mu      sync.Mutex
)

var db *bbolt.DB

func InitDB() {
	var err error
	db, err = bbolt.Open("whois.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}

	db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("domains"))
		return err
	})
}

func SaveDomain(domain DomainInfo) {
	db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("domains"))
		data, _ := json.Marshal(domain)
		return b.Put([]byte(domain.Domain), data)
	})
}

func LoadDomainsFromDB() {
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
}

func DeleteDomain(domain string) {
	db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("domains"))
		return b.Delete([]byte(domain))
	})
}

func CloseDB() {
	db.Close()
}

func main() {
	// Ініціалізація бази даних
	InitDB()
	defer CloseDB()

	// Завантажуємо домени з БД при старті
	LoadDomainsFromDB()

	r := mux.NewRouter()
	r.HandleFunc("/", serveIndex).Methods("GET")
	r.HandleFunc("/check", checkDomain).Methods("POST")
	r.HandleFunc("/delete", deleteDomain).Methods("POST")

	log.Println("Сервер запущено на :8080")
	http.ListenAndServe(":8080", r)
}

// serveIndex віддає HTML-файл
func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
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

	info := DomainInfo{
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

	// Видаляємо з БД
	DeleteDomain(domain)

	delete(domains, domain)
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
	tmpl := `
<tr id="row-{{.Domain}}" class="{{if .IsExpired}}table-danger{{end}}">
    <td>{{.Domain}}</td>
    <td>{{.DomainExpire}}</td>
    <td>{{.SSLExpires}}</td>
    <td>
        <button class="btn btn-sm btn-danger" hx-post="/delete" hx-vals='{"domain":"{{.Domain}}"}' hx-target="#row-{{.Domain}}" hx-swap="outerHTML">
            ❌ Видалити
        </button>
    </td>
</tr>`
	t := template.Must(template.New("row").Parse(tmpl))
	t.Execute(w, domain)
}
