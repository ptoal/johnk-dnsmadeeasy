package dnsmadeeasy

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	DNSManagedPath string = "/dns/managed/"
	DNSRecordsPath string = "{domainId}/records"
)

type BaseURL string

const (
	Sandbox BaseURL = "https://api.sandbox.dnsmadeeasy.com/V2.0/"
	Prod    BaseURL = "https://api.dnsmadeeasy.com/V2.0/"
)

type Client struct {
	APIToken  string
	APISecret string
	BaseURL   BaseURL
	resty     *resty.Client
}

func GetClient(APIToken string, APISecret string, url BaseURL) *Client {
	r := resty.New().SetBaseURL(string(url)).SetDebug(false)
	return &Client{APIToken, APISecret, url, r}
}

func (c *Client) addAuthHeaders(req *resty.Request) {
	requestDate := time.Now().UTC().Format(http.TimeFormat)

	// Calculate the hexadecimal HMAC SHA1 of requestDate using APIKey
	key := []byte(c.APISecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(requestDate))
	hmacString := hex.EncodeToString(h.Sum(nil))

	req.Header.Add("X-Dnsme-Apikey", c.APIToken)
	req.Header.Add("X-Dnsme-Requestdate", requestDate)
	req.Header.Add("X-Dnsme-Hmac", hmacString)
}

func (c *Client) newRequest() *resty.Request {
	req := c.resty.R().EnableTrace().ExpectContentType("application/json").
		SetHeader("Content-Type", "application/json")
	c.addAuthHeaders(req)
	return req
}

type Domain struct {
	ID                 int      `json:"id"`
	Name               string   `json:"name"`
	CreatedAt          int      `json:"created"`
	UpdatedAt          int      `json:"updated"`
	FolderID           int      `json:"folderId"`
	ProcessMulti       bool     `json:"processMulti"`
	ActiveThirdParties []string `json:"activeThirdParties"`
	GtdEnabled         bool     `json:"gtdEnabled"`
	PendingActionID    int      `json:"pendingActionId"`
}

type DomainsResp struct {
	TotalRecords int      `json:"totalRecords"`
	TotalPages   int      `json:"totalPages"`
	Domains      []Domain `json:"data"`
	CurrentPage  int      `json:"page"`
}

func (c *Client) EnumerateDomains() (map[string]int, error) {
	domains := map[string]int{}

	var respDomains DomainsResp
	resp, err := c.newRequest().
		SetResult(&respDomains).
		Get(DNSManagedPath)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != 200 {
		fmt.Printf("WARN: request returned status %d (%s)", resp.StatusCode(), resp.Status())
	}

	for _, domain := range respDomains.Domains {
		domains[domain.Name] = domain.ID
	}

	return domains, nil
}

type Record struct {
	Name        string `json:"name"`
	ID          int    `json:"id"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Source      int    `json:"source"`
	Ttl         int    `json:"ttl"`
	GtdLocation string `json:"gtdLocation"`
	SourceId    int    `json:"sourceId"`
	Failover    bool   `json:"failover"`
	Monitor     bool   `json:"monitor"`
	HardLink    bool   `json:"hardLink"`
	DynamicDns  bool   `json:"dynamicDns"`
	Failed      bool   `json:"failed"`
}

type RecordsResp struct {
	TotalRecords int      `json:"totalRecords"`
	TotalPages   int      `json:"totalPages"`
	Records      []Record `json:"data"`
	CurrentPage  int      `json:"page"`
}

func (c *Client) EnumerateRecords(domainId int) ([]Record, error) {
	var respRecords RecordsResp
	req := c.newRequest().
		SetResult(&respRecords).
		SetDebug(true).
		SetPathParam("domainId", fmt.Sprint(domainId))
	resp, err := req.Get(DNSManagedPath + DNSRecordsPath)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != 200 {
		fmt.Printf("WARN: request returned status %d (%s)", resp.StatusCode(), resp.Status())
	}

	return respRecords.Records, nil
}
