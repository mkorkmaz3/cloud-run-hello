package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "strings"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
    docs "google.golang.org/api/docs/v1"
    "google.golang.org/api/option"
)


type docData struct {
    title   string
    content string
}

// Retrieves a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
    tokFile := "token.json"
    tok, err := tokenFromFile(tokFile)
    if err != nil {
        tok = getTokenFromWeb(config)
        saveToken(tokFile, tok)
    }
    return config.Client(context.Background(), tok)
}

// Requests a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
    authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
    fmt.Printf("Go to the following link in your browser then type the "+
        "authorization code: \n%v\n", authURL)

    var authCode string
    // if _, err := fmt.Scan(&authCode); err != nil {
    //     log.Fatalf("Unable to read authorization code: %v", err)
    // }
    authCode = "4/1AX4XfWhD-iHgPtX8bHYzc5NayvS5NB7qnduAiqvAHkKhNOw7KY5Fg060QW0"
    tok, err := config.Exchange(oauth2.NoContext, authCode)
    if err != nil {
        log.Fatalf("Unable to retrieve token from web: %v", err)
    }
    return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
    f, err := os.Open(file)
    defer f.Close()
    if err != nil {
        return nil, err
    }
    tok := &oauth2.Token{}
    err = json.NewDecoder(f).Decode(tok)
    return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
    fmt.Printf("Saving credential file to: %s\n", path)
    f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
    defer f.Close()
    if err != nil {
        log.Fatalf("Unable to cache OAuth token: %v", err)
    }
    json.NewEncoder(f).Encode(token)
}
func readBodyParagraphs(elements []*docs.StructuralElement) string {
	var str strings.Builder
	for _, element := range elements {
        if element.Paragraph != nil{
            for _, pe := range element.Paragraph.Elements {
                if pe.TextRun != nil {
                    str.WriteString(pe.TextRun.Content)
                }
            }
        }
    }
    return str.String()
}
func readTitleAndBody(docId string) docData{
 ctx := context.Background()
 b, err := ioutil.ReadFile("credentials.json")
 if err != nil {
     log.Fatalf("Unable to read client secret file(credentials.json): %v", err)
 }

 // If modifying these scopes, delete your previously saved token.json.
 config, err := google.ConfigFromJSON(b, "https://www.googleapis.com/auth/documents.readonly")
 if err != nil {
     log.Fatalf("Unable to parse client secret file to config: %v", err)
 }
 client := getClient(config)

 srv, err := docs.NewService(ctx, option.WithHTTPClient(client))
 if err != nil {
     log.Fatalf("Unable to retrieve Docs client: %v", err)
 }

 // Prints the title of the requested doc:
 //TODO(mkorkmaz) use docID param
 doc, err := srv.Documents.Get("1j_yE4zEiSJcGXcLoXew_vrCBLCI9iK8fhy4RgpSh32k").Do()
 if err != nil {
     log.Fatalf("Unable to retrieve data from document: %v", err)
 }
 dd := docData{}
 dd.title = doc.Title
 dd.content = readBodyParagraphs(doc.Body.Content)
 return dd
}

