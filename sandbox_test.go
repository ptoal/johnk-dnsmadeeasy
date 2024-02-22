package dnsmadeeasy

import (
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/tjarratt/babble"
)

func createTestDomain(t *testing.T, client *Client) (Domain, error) {
	babbler := babble.NewBabbler()
	testDomainName := fmt.Sprintf("%s.testing", babbler.Babble())

	// create a domain for testing within this run
	domain, err := client.CreateDomain(testDomainName)
	if err != nil {
		return Domain{}, err
	}
	t.Logf("Created domain %s\n", testDomainName)

	return domain, nil
}

// This test might take up to 10 minutes and
func deleteTestDomain(t *testing.T, client *Client, domainID int) {
	maxRetries := 10
	waitSeconds, _ := time.ParseDuration("30s")
	tries := 0

	// Since domains might still be in the "Pending Creaton" state
	// due to the short lifetime of our tests, we need to poll the
	// PendingActionID to see
	for {
		domain, err := client.GetDomain(domainID)
		if err != nil {
			t.Error(err)
		}
		if domain.PendingActionID == 0 {
			break
		}
		tries += 1
		if tries >= maxRetries {
			t.Errorf("exceeded max retries deleting domain %s", domain.Name)
		}
		time.Sleep(waitSeconds)
	}

	err := client.DeleteDomain(domainID)
	if err != nil {
		t.Error(err)
	}
}

func TestSandboxIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// load environment for integration tests
	err := godotenv.Load(os.ExpandEnv(".env"))
	if err != nil {
		log.Fatalf("Error getting env %v\n", err)
	}

	apiToken := os.Getenv("DME_API_TOKEN")
	apiSecret := os.Getenv("DME_API_SECRET")

	// set global client for use in testing
	client := GetClient(apiToken, apiSecret, Sandbox)
	toCreate := 50

	var testDomains []Domain
	t.Run("create test domain", func(t *testing.T) {
		domain, err := createTestDomain(t, client)
		if err != nil {
			t.Errorf("Failed: %s", err)
		}
		testDomains = append(testDomains, domain)
	})
	t.Run("create records", func(t *testing.T) {
		var records []Record
		for idx := range toCreate {
			name := fmt.Sprint("test-", idx)
			records = append(records, Record{Name: name, Type: "A", Value: "1.1.1.1", GtdLocation: "DEFAULT", Ttl: 1800})
		}
		createdRecords, err := client.CreateRecords(testDomains[0].ID, records)
		if err != nil {
			t.Error(err)
		}
		assert.Len(t, createdRecords, toCreate)
	})

	t.Run("enumerate records", func(t *testing.T) {
		records, err := client.EnumerateRecords(testDomains[0].ID)
		if err != nil {
			t.Error(err)
		}
		assert.Len(t, records, toCreate)
	})
	/*t.Run("update records", func(t *testing.T) {

	})*/
	t.Run("delete all records", func(t *testing.T) {
		err := client.DeleteAllRecords(testDomains[0].ID)
		if err != nil {
			t.Error(err)
		}
		records, err := client.EnumerateRecords(testDomains[0].ID)
		if err != nil {
			t.Error(err)
		}
		assert.Empty(t, records)
	})

	t.Run("Test IdForDomain cache", func(t *testing.T) {
		// call function to populate cache
		id, err := client.IdForDomain(testDomains[0].Name)
		if err != nil {
			t.Error(err)
		}
		assert.Equal(t, testDomains[0].ID, id)

		// create new domain
		newDomain, err := createTestDomain(t, client)
		if err != nil {
			t.Error(err)
		}

		// add newDomain to the list to be deleted later
		testDomains = append(testDomains, newDomain)

		// get the ID for the newly created domain name
		newId, err := client.IdForDomain(newDomain.Name)
		if err != nil {
			t.Error(err)
		}
		assert.Equal(t, newDomain.ID, newId)
	})
	t.Run("Cleanup test domains", func(t *testing.T) {
		for _, domain := range testDomains {
			t.Run(fmt.Sprint("Deleting ", domain.Name), func(t *testing.T) {
				deleteTestDomain(t, client, domain.ID)
			})
		}
	})
}
