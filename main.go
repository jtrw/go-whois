package main

import (
	"context"
	"embed"
	"encoding/json"
	server "go-whios/app/server"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
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
}
