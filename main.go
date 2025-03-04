package main

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	server "go-whios/app/server"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jessevdk/go-flags"
	"github.com/likexian/whois"
	"go.etcd.io/bbolt"
)

// DomainInfo структура для збереження інформації про домен
type DomainInfo struct {
	Uuid         string
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
var webFS embed.FS

type Options struct {
	Listen         string        `short:"l" long:"listen" env:"LISTEN_SERVER" default:":8080" description:"listen address"`
	PinSize        int           `long:"pinszie" env:"PIN_SIZE" default:"5" description:"pin size"`
	MaxExpire      time.Duration `long:"expire" env:"MAX_EXPIRE" default:"24h" description:"max lifetime"`
	MaxPinAttempts int           `long:"pinattempts" env:"PIN_ATTEMPTS" default:"3" description:"max attempts to enter pin"`
	WebRoot        string        `long:"web" env:"WEB" default:"./web" description:"web ui location"`
	AuthLogin      string        `long:"auth-login" env:"AUTH_LOGIN" default:"admin" description:"auth login"`
	AuthPassword   string        `long:"auth-password" env:"AUTH_PASSWORD" default:"admin" description:"auth password"`
}

func InitDB() *bbolt.DB {
	db, err := bbolt.Open("jWhois.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("domains"))
		return err
	})

	return db
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

var revision string

func main() {
	log.Printf("Micro Whios redis %s\n", revision)

	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()
	if err != nil {

		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if x := recover(); x != nil {
			log.Printf("[WARN] run time panic:\n%v", x)
			panic(x)
		}

		// catch signal and invoke graceful termination
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		log.Printf("[WARN] interrupt signal")
		cancel()
	}()

	db := InitDB()

	srv := server.Server{
		Listen:         opts.Listen,
		PinSize:        opts.PinSize,
		MaxExpire:      opts.MaxExpire,
		MaxPinAttempts: opts.MaxPinAttempts,
		WebRoot:        opts.WebRoot,
		WebFS:          webFS,
		Version:        revision,
		AuthLogin:      opts.AuthLogin,
		AuthPassword:   opts.AuthPassword,
		Context:        ctx,
		DB:             db,
	}
	if err := srv.Run(ctx); err != nil {
		log.Printf("[ERROR] failed, %+v", err)
	}
	return
	// Ініціалізація бази даних

	//defer CloseDB()

	// Завантажуємо домени з БД при старті
	//LoadDomainsFromDB()

	//r := mux.NewRouter()

	//add static folder
	//r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	//r.HandleFunc("/", serveIndex).Methods("GET")
	//r.HandleFunc("/check", checkDomain).Methods("POST")
	//r.HandleFunc("/delete", deleteDomain).Methods("POST")
	//r.HandleFunc("/domains", listDomains).Methods("GET")

	//log.Println("Сервер запущено на :8080")
	//http.ListenAndServe(":8080", r)
}

// serveIndex віддає HTML-файл
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
