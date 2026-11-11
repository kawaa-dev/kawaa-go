// Webhook handler example for Kawaa Go SDK
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"kawaa.com/go/kawaa"
)

func main() {
	// Get webhook secret from environment. Never fall back to a placeholder:
	// anyone could sign a forged webhook with it.
	webhookSecret := os.Getenv("KAWAA_WEBHOOK_SECRET")
	if strings.TrimSpace(webhookSecret) == "" {
		log.Fatal("KAWAA_WEBHOOK_SECRET is not set. Set it to your webhook signing secret before starting this example.")
	}

	// Create webhook handler. It checks the X-Kawaa-Signature-V2 header and
	// refuses a delivery signed more than 300 seconds ago (a replay). Pass
	// kawaa.WithWebhookTolerance to change that window. A request signed only
	// with the legacy X-Kawaa-Signature header is refused unless you pass
	// kawaa.WithLegacyWebhookSignature(), which accepts replayable requests.
	handler := kawaa.NewWebhookHandler(webhookSecret)

	// Handle incoming webhooks. Registered webhooks deliver an envelope
	// {event, data: {...}, webhook_id, timestamp}; decode the event-specific
	// data with the typed accessors.
	http.HandleFunc("/webhook", handler.HTTPHandler(func(event *kawaa.WebhookEvent) error {
		fmt.Printf("Received webhook event: %s (webhook %s)\n", event.Event, event.WebhookID)

		switch event.Event {
		case kawaa.EventJobCompleted:
			data, err := event.JobCompleted()
			if err != nil {
				return err
			}
			fmt.Printf("Job ID: %s\n", data.JobID)
			fmt.Printf("Status: %s\n", data.Status)
			fmt.Printf("Total emails: %d\n", data.TotalEmails)
			if data.Summary != nil {
				fmt.Printf("Valid: %d\n", data.Summary.Valid)
				fmt.Printf("Invalid: %d\n", data.Summary.Invalid)
				fmt.Printf("Risky: %d\n", data.Summary.Risky)
				fmt.Printf("Unknown: %d\n", data.Summary.Unknown)
			}
			if data.DownloadURL != "" {
				fmt.Printf("Download URL: %s\n", data.DownloadURL)
			}
		case kawaa.EventVerificationCompleted:
			data, err := event.VerificationCompleted()
			if err != nil {
				return err
			}
			fmt.Printf("Verification %s finished: %s\n", data.JobID, data.Status)
		case kawaa.EventCreditsLow:
			data, err := event.CreditsLow()
			if err != nil {
				return err
			}
			fmt.Printf("Credits low: %g remaining\n", data.CreditsRemaining)
		default:
			fmt.Printf("Unhandled event; raw data: %s\n", string(event.Data))
		}

		// Here you would typically:
		// - Update your database
		// - Send notification to user
		// - Download and process results

		return nil
	}))

	// Alternative: Manual webhook handling
	http.HandleFunc("/webhook-manual", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		event, err := handler.ParseRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if data, err := event.JobCompleted(); err == nil && data.Summary != nil {
			log.Printf("Job %s completed with %d valid emails\n", data.JobID, data.Summary.Valid)
		} else {
			log.Printf("Received %s event\n", event.Event)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Starting webhook server on :%s\n", port)
	fmt.Println("Endpoints:")
	fmt.Println("  POST /webhook        - Auto-handled webhook")
	fmt.Println("  POST /webhook-manual - Manual webhook handling")

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
