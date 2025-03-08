package db

import (
	"encoding/json"
	"log"

	"go.etcd.io/bbolt"
)

var db *bbolt.DB

const DOMAIN_BUCKET = "domains"

type DomainInfo struct {
	Uuid         string
	Domain       string
	WhoisData    string
	SSLValid     bool
	SSLExpires   string
	DomainExpire string
	IsExpired    bool
}

func InitDB() {
	var err error
	db, err = bbolt.Open("whois.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}

	db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(DOMAIN_BUCKET))
		return err
	})
}

func SaveDomain(domain DomainInfo) {
	db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(DOMAIN_BUCKET))
		data, _ := json.Marshal(domain)
		return b.Put([]byte(domain.Domain), data)
	})
}

func LoadDomainsFromDB() {
	db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(DOMAIN_BUCKET))
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
		b := tx.Bucket([]byte(DOMAIN_BUCKET))
		return b.Delete([]byte(domain))
	})
}

func CloseDB() {
	db.Close()
}
