package dnsmadeeasy

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	DNSManagedPath string = "/dns/managed/"
	DNSRecordsPath string = "{domainId}/records"
	DNSRecordPath  string = "{domainId}/records/{recordId}"
)

type BaseURL string

const (
	Sandbox BaseURL = "https://api.sandbox.dnsmadeeasy.com/V2.0/"
	Prod    BaseURL = "https://api.dnsmadeeasy.com/V2.0/"
)

type Client struct {
	APIToken    string
	APISecret   string
	BaseURL     BaseURL
	resty       *resty.Client
	zoneIdCache map[string]int
}

func checkRespForError(resp *resty.Response, err error) (*resty.Response, error) {
	if err != nil {
		return resp, err
	}

	var data map[string]interface{}

	if err := json.Unmarshal(resp.Body(), &data); err != nil {
		return resp, err
	}

	if data["error"] == nil {
		return resp, err
	}

	//translate the array of strings that is DME's error json element
	// ie { "error": [ "", "" ] }
	resp_errors := data["error"].([]interface{})
	if len(resp_errors) > 0 {
		var error string
		if len(resp_errors) == 1 {
			error = resp_errors[0].(string)
		} else {
			for idx, err := range resp_errors {
				error += fmt.Sprintf("%d: %s\n", idx, err.(string))
			}
		}
		return resp, errors.New(error)
	}

	return resp, err
}

func GetClient(APIToken string, APISecret string, url BaseURL) *Client {
	r := resty.New().SetBaseURL(string(url)).SetDebug(false)
	return &Client{APIToken, APISecret, url, r, nil}
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
	_, err := checkRespForError(c.newRequest().
		SetResult(&respDomains).
		Get(DNSManagedPath))
	if err != nil {
		return nil, err
	}

	for _, domain := range respDomains.Domains {
		domains[domain.Name] = domain.ID
	}

	return domains, nil
}

func (c *Client) IdForDomain(domain string) (int, error) {
	justPopulated := false
	if c.zoneIdCache == nil {
		domainMap, err := c.EnumerateDomains()
		if err != nil {
			return 0, err
		}
		c.zoneIdCache = domainMap
		justPopulated = true
	}

	zoneId, ok := c.zoneIdCache[domain]
	if ok {
		return zoneId, nil
	} else {
		// if we didn't just populate the cache, refresh it in case
		// our domain exists now
		if !justPopulated {
			domainMap, err := c.EnumerateDomains()
			if err != nil {
				return 0, err
			}
			c.zoneIdCache = domainMap
			justPopulated = true
		}
		zoneId, ok := c.zoneIdCache[domain]
		if ok {
			return zoneId, nil
		}
	}

	return 0, errors.New("Domain not found")
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
		SetDebug(false).
		SetPathParam("domainId", fmt.Sprint(domainId))

	_, err := checkRespForError(req.Get(DNSManagedPath + DNSRecordsPath))
	if err != nil {
		return nil, err
	}

	return respRecords.Records, nil
}

func (c *Client) DeleteRecords(domainId int, records []int) ([]int, error) {
	var deleted []int

	for _, id := range records {
		req := c.newRequest().
			SetDebug(false).
			SetPathParam("domainId", fmt.Sprint(domainId)).
			SetPathParam("recordId", fmt.Sprint(id))

		_, err := checkRespForError(req.Delete(DNSManagedPath + DNSRecordPath))
		if err != nil {
			// TODO: should we be returning both a result and a collection of
			// errors encountered along the way?
			fmt.Printf("Error deleting record %d from domain %d: %s\n", id, domainId, err)
			continue
		}
		deleted = append(deleted, id)
	}

	return deleted, nil
}

func (c *Client) CreateRecord(domainId int, record Record) (Record, error) {
	var newRecord Record

	req := c.newRequest().
		SetDebug(true).
		SetResult(&newRecord).
		SetBody(&record).
		SetPathParam("domainId", fmt.Sprint(domainId))

	_, err := checkRespForError(req.Post(DNSManagedPath + DNSRecordsPath))
	if err != nil {
		return Record{}, err
	}

	return newRecord, nil
}
