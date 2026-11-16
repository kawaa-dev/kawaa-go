// Basic usage example for Kawaa Go SDK
package main

import (
	"context"
	"fmt"
	"log"
	"os"

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

	fmt.Println("=== Kawaa Go SDK Examples ===")
	fmt.Println()

	// Example 1: Single Email Verification
	fmt.Println("1. Single Email Verification")
	fmt.Println("----------------------------------------")

	result, err := client.Verify(ctx, "test@example.com")
	if err != nil {
		log.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Email: %s\n", result.Email)
		fmt.Printf("Status: %s\n", result.Status)
		fmt.Printf("Score: %d\n", result.Score)
		fmt.Printf("Valid: %t\n", result.IsValid())
		fmt.Printf("Deliverable: %t\n", result.IsDeliverable())
		fmt.Printf("\nFlags:\n")
		fmt.Printf("  - Disposable: %t\n", result.Flags.Disposable)
		fmt.Printf("  - Role: %t\n", result.Flags.Role)
		fmt.Printf("  - Free Provider: %t\n", result.Flags.FreeProvider)
		if result.Flags.CatchAllMeasured {
			fmt.Printf("  - Catch-all: %t\n", result.Flags.CatchAll)
		} else {
			fmt.Printf("  - Catch-all: not measured\n")
		}

		if result.Suggestion != "" {
			fmt.Printf("\nSuggestion: Did you mean %s?\n", result.Suggestion)
		}
		if result.CreditsUsed != nil {
			// 1 for a fresh check, 0.5 for a cached one.
			fmt.Printf("Credits used: %g\n", *result.CreditsUsed)
		}
		if result.IsPending() {
			fmt.Printf("Still verifying; poll job %s with GetJobStatus\n", result.JobID)
		}
	}
	fmt.Println()

	// Example 2: Email Finder
	fmt.Println("2. Email Finder")
	fmt.Println("----------------------------------------")

	findResult, err := client.Find(ctx, "John", "Smith", "example.com")
	if err != nil {
		log.Printf("Error: %v\n", err)
	} else {
		if findResult.Found() {
			fmt.Printf("Found: %s\n", findResult.Email)
			fmt.Printf("Confidence: %d%%\n", findResult.Confidence)
			fmt.Printf("Pattern: %s\n", findResult.Pattern)
			fmt.Printf("Verified: %t\n", findResult.Verified)
		} else {
			fmt.Println("Email not found")
		}
		fmt.Printf("Credits used: %g\n", findResult.CreditsUsed)
	}
	fmt.Println()

	// Example 3: Domain Search
	fmt.Println("3. Domain Search")
	fmt.Println("----------------------------------------")

	domainResult, err := client.DomainSearch(ctx, "example.com")
	if err != nil {
		log.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Domain: %s\n", domainResult.Domain)
		if domainResult.IsProcessing() {
			fmt.Println("Discovery still processing - re-call DomainSearch to poll")
		}
		fmt.Printf("Emails found: %d\n", domainResult.EmailCount)
		fmt.Printf("Patterns checked: %d\n", domainResult.PatternsChecked)
		fmt.Printf("From cache: %t\n", domainResult.FromCache)

		if len(domainResult.Emails) > 0 {
			fmt.Println("\nEmails:")
			for _, email := range domainResult.Emails {
				fmt.Printf("  - %s: %s\n", email.Email, email.Status)
			}
		}
		fmt.Printf("Credits used: %g\n", domainResult.CreditsUsed)
	}
	fmt.Println()

	// Example 4: Account Info
	fmt.Println("4. Account Info")
	fmt.Println("----------------------------------------")

	account, err := client.GetAccount(ctx)
	if err != nil {
		log.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("User ID: %s\n", account.UserID)
		fmt.Printf("Email: %s\n", account.Email)
		fmt.Printf("Plan: %s\n", account.Plan)
		fmt.Printf("Credits remaining: %g\n", account.CreditsRemaining) // fractional: a cached check costs 0.5
		if account.CreditsUsed != nil {
			fmt.Printf("Credits used: %g\n", *account.CreditsUsed)
		} else if account.UsageWithheld {
			fmt.Println("Credits used: withheld (this key has no analytics:read scope)")
		}
	}

	fmt.Println()
	fmt.Println("=== Examples Complete ===")
}
