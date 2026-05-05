package nic

import "encoding/xml"

// response is the top-level NIC.RU API XML envelope.
type response struct {
	XMLName xml.Name     `xml:"response"`
	Status  string       `xml:"status"`
	Data    responseData `xml:"data"`
}

type responseData struct {
	Zone zoneData `xml:"zone"`
}

type zoneData struct {
	Name    string    `xml:"name,attr"`
	Records []rrEntry `xml:"rr"`
}

// rrEntry represents a single DNS resource record returned by the API.
type rrEntry struct {
	ID   int    `xml:"id,attr"`
	Name string `xml:"name"`
	TTL  int    `xml:"ttl"`
	Type string `xml:"type"`
	TXT  string `xml:"txt"`
}

// addRecordRequest is the XML body sent when creating a new record.
type addRecordRequest struct {
	XMLName xml.Name  `xml:"request"`
	RRList  []txtRR   `xml:"rr-list>rr"`
}

type txtRR struct {
	Name string    `xml:"name"`
	TTL  int       `xml:"ttl"`
	Type string    `xml:"type"`
	TXT  txtString `xml:"txt"`
}

type txtString struct {
	Value string `xml:"string"`
}

// oauthTokenResponse is the JSON body from NIC.RU OAuth endpoint.
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// tokenCache is persisted to disk as JSON.
type tokenCache struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	CreatedAt   int64  `json:"created_at"`
}
