
// The quickstart program is an example of using the Data Loss Prevention API.
package main

import (
        "context"
        "fmt"
        "log"
		// "strings"

        dlp "cloud.google.com/go/dlp/apiv2"
        dlppb "google.golang.org/genproto/googleapis/privacy/dlp/v2"
)

func dlpText(input string) int{
        ctx := context.Background()

        projectID := "eventflow-qa"

        // Creates a DLP client.
        client, err := dlp.NewClient(ctx)
        if err != nil {
                log.Fatalf("error creating DLP client: %v", err)
        }
        defer client.Close()

        // The string to inspect.
        // input := "Robert Frost"

        // The minimum likelihood required before returning a match.
        minLikelihood := dlppb.Likelihood_POSSIBLE

        // The maximum number of findings to report (0 = server maximum).
        maxFindings := int32(0)

        // Whether to include the matching string.
        includeQuote := true

        // The infoTypes of information to match.
        infoTypes := []*dlppb.InfoType{
                {
                        Name: "EMAIL_ADDRESS",
                },
                {
                        Name: "AGE",
                },
                {
                        Name: "CREDIT_CARD_NUMBER",
                },
                {
                        Name: "PASSWORD",
                },
                {
                        Name: "AUTH_TOKEN",
                },
                {
                        Name: "MEDICAL_TERM",
                },
        }

        // Construct item to inspect.
        item := &dlppb.ContentItem{
                DataItem: &dlppb.ContentItem_Value{
                        Value: input,
                },
        }

        // Construct request.
        req := &dlppb.InspectContentRequest{
                Parent: fmt.Sprintf("projects/%s/locations/global", projectID),
                InspectConfig: &dlppb.InspectConfig{
                        InfoTypes:     infoTypes,
                        MinLikelihood: minLikelihood,
                        Limits: &dlppb.InspectConfig_FindingLimits{
                                MaxFindingsPerRequest: maxFindings,
                        },
                        IncludeQuote: includeQuote,
                },
                Item: item,
        }

        // Run request.
        resp, err := client.InspectContent(ctx, req)
        if err != nil {
                log.Fatal(err)
        }
        findings := resp.GetResult().GetFindings()
        if len(findings) == 0 {
                fmt.Println("No findings.")
        }
		// var str strings.Builder
        fmt.Println("Findings:")
        for _, f := range findings {
                if includeQuote {
                        fmt.Println("\tQuote: ", f.GetQuote())
                }
                fmt.Println("\tInfo type: ", f.GetInfoType().GetName())
                fmt.Println("\tLikelihood: ", f.GetLikelihood())
        }
		return len(findings)

}