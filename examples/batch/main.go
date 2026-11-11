// Batch verification example for Kawaa Go SDK
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"kawaa.com/go/kawaa"
)

func main() {
	// Get API key from environment
	apiKey := os.Getenv("KAWAA_API_KEY")
	if apiKey == "" {
		apiKey = "your-api-key"
	}

	// Create client
	client := kawaa.NewClient(apiKey)
	ctx := context.Background()

	fmt.Println("=== Batch Verification Example ===")
	fmt.Println()

	emails := []string{
		"john@example.com",
		"jane@example.com",
		"support@example.com",
		"invalid-email",
		"john@example.com", // Duplicate
	}

	fmt.Printf("Submitting %d emails for verification...\n\n", len(emails))

	// Start batch job
	fmt.Println("Starting batch job...")
	job, err := client.VerifyBatch(ctx, emails)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}

	fmt.Printf("Job ID: %s\n", job.JobID)
	fmt.Printf("Status: %s\n", job.Status)
	fmt.Printf("Total submitted: %d\n", job.TotalSubmitted)
	fmt.Printf("Duplicates removed: %d\n", job.DuplicatesRemoved)
	fmt.Printf("Unique emails: %d\n", job.UniqueEmails)
	// Credit figures are float64: cached verifications cost 0.5. CreditsUsed
	// is nil on a replay of a batch already accepted under the same key; the
	// job (GetJobStatus) has its charge.
	if job.CreditsUsed != nil {
		fmt.Printf("Credits used: %g\n", *job.CreditsUsed)
	}
	if job.CreditsRemaining != nil {
		fmt.Printf("Credits remaining: %g\n", *job.CreditsRemaining)
	}

	fmt.Println("\nWaiting for completion...")

	// Wait for job to complete
	result, err := client.WaitForJob(ctx, job.JobID, 2*time.Second, 60*time.Second)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}

	fmt.Println("\n=== Results ===")
	fmt.Printf("Status: %s\n", result.Status)
	fmt.Printf("Progress: %.1f%%\n", result.ProgressPercent)
	fmt.Printf("Valid: %d\n", result.ValidCount)
	fmt.Printf("Invalid: %d\n", result.InvalidCount)
	fmt.Printf("Risky: %d\n", result.RiskyCount)
	fmt.Printf("Unknown: %d\n", result.UnknownCount)

	fmt.Println("\nIndividual Results:")
	for _, r := range result.Results {
		fmt.Printf("  %s: %-8s (score: %d)\n", r.Email, r.Status, r.Score)
	}

	fmt.Println()
	fmt.Println("=== Example Complete ===")
}
