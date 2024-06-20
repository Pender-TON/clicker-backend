package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client

type VerifyRequest struct {
    Hash string `json:"hash"`
    Data string `json:"data"`
}

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
	var err error
	err = godotenv.Load()
	if err != nil {
    	log.Fatal("Error loading .env file")
  	}	
    clientOptions := options.Client().ApplyURI(os.Getenv("MONGODB_CONNECTION_STRING"))
    client, err = mongo.Connect(ctx, clientOptions)
    if err != nil {
        log.Fatal(err)
    }

    err = client.Ping(ctx, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Connected to MongoDB Atlas!")

	err = godotenv.Load()
	if err != nil {
    	log.Fatal("Error loading .env file")
  	}

    token := os.Getenv("BOT_TOKEN")
    if token == "" {
        panic("TOKEN environment variable is empty")
    }

    router := mux.NewRouter()
    router.Use(enableCors)
    router.HandleFunc("/updateField", updateFieldHandler).Methods("POST", "OPTIONS")
    router.HandleFunc("/createDocument", createDocumentHandler).Methods("POST", "OPTIONS")
    router.HandleFunc("/getDocument", getDocumentHandler).Methods("GET", "OPTIONS")
    router.HandleFunc("/verifySignature", verifySignatureHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/dbInit", dbInit).Methods("POST", "OPTIONS")
    router.HandleFunc("/getPosition", getPositionHandler).Methods("POST", "OPTIONS")

    err = http.ListenAndServeTLS(":443", "cert.pem", "key.pem", router)
    if err != nil {
        log.Fatal(err)
    }    
}

func enableCors(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
        w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
        
        // Check if the request method is OPTIONS
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}


func updateFieldHandler(w http.ResponseWriter, r *http.Request) {
	type UpdateRequest struct {
        UserID   int    `json:"userId"`
        UserName string `json:"userName"`
		Count   int    `json:"count"`
    }

    var req UpdateRequest
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    collection := client.Database("pender-clicks").Collection("clicks-01")
    filter := bson.M{"userId": req.UserID, "userName": req.UserName}

    var currentDoc struct {
        Count int `bson:"count"`
    }
    err = collection.FindOne(context.TODO(), filter).Decode(&currentDoc)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            http.Error(w, "No document found with the provided userId and userName", http.StatusNotFound)
            return
        }

        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    if req.Count <= currentDoc.Count {
        fmt.Fprint(w, currentDoc.Count)
        return
    }

    update := bson.M{"$set": bson.M{
        "userId":   req.UserID,
        "userName": req.UserName,
        "count":    req.Count,
    }}

    _, err = collection.UpdateOne(context.TODO(), filter, update)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Fprint(w, req.Count)
}

func createDocument(userId int, userName string, count int) error {
    collection := client.Database("pender-clicks").Collection("clicks-01")
    document := bson.M{
        "userId":   userId,
        "userName": userName,
        "count":    count,
    }

    _, err := collection.InsertOne(context.TODO(), document)
    return err
}

func createDocumentHandler(w http.ResponseWriter, r *http.Request) {
    var req InitRequest
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    err = createDocument(req.UserID, req.UserName, req.Count)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
}

func getDocumentHandler(w http.ResponseWriter, r *http.Request) {
    collection := client.Database("pender-clicks").Collection("clicks-01")

    opts := options.Find()
    opts.SetSort(bson.D{{Key: "count", Value: -1}})
    opts.SetLimit(5)

    cursor, err := collection.Find(context.TODO(), bson.D{{}}, opts)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    var results []bson.M
    if err = cursor.All(context.TODO(), &results); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    formattedResults := make([]string, len(results))
    for i, result := range results {
        formattedResults[i] = fmt.Sprintf("%s : %v", result["userName"], result["count"])
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(formattedResults)
}

type InitRequest struct {
    UserID   int    `json:"userId"`
    UserName string `json:"userName"`
    Count    int    `json:"count"`
}

func getPositionHandler(w http.ResponseWriter, r *http.Request) {
    // Define a struct to hold the incoming JSON data
    type RequestData struct {
        UserId   int    `json:"userId"`
    }

    // Decode the JSON request body into the struct
    var requestData RequestData
    err := json.NewDecoder(r.Body).Decode(&requestData)
    if err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Use the userId from the request data
    userId := requestData.UserId

    // Query the MongoDB collection and sort the documents in descending order by the 'count' field
    collection := client.Database("pender-clicks").Collection("clicks-01")
    cursor, err := collection.Find(context.TODO(), bson.M{}, options.Find().SetSort(bson.D{{Key: "count", Value: -1}}))
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    var results []bson.M
    if err = cursor.All(context.TODO(), &results); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Iterate over the sorted documents to find the position of the specified userId
    position := -1
    for i, result := range results {
        dbUserId, ok := result["userId"].(int64)
        if !ok {
            dbUserId32, ok := result["userId"].(int32)
            if ok {
                dbUserId = int64(dbUserId32)
            } else {
                fmt.Printf("Unexpected type for userId: %T\n", result["userId"])
                continue
            }
        }
    
        if dbUserId == int64(userId) {
            position = i + 1
            break
        }
    }

    // Return the position of the specified userId
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]int{"position": position})
}

func dbInit(w http.ResponseWriter, r *http.Request) {
    var req InitRequest
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    collection := client.Database("pender-clicks").Collection("clicks-01")
    filter := bson.M{
        "userId":   req.UserID,
        "userName": req.UserName,
    }

    var result struct {
        Count int `bson:"count"`
    }
    err = collection.FindOne(context.TODO(), filter).Decode(&result)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            err = createDocument(req.UserID, req.UserName, req.Count)
            if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }

            w.WriteHeader(http.StatusCreated)
            return
        }

        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Fprint(w, result.Count)
}

func verifySignatureHandler(w http.ResponseWriter, r *http.Request) {
    // Load .env file
    err := godotenv.Load()
    if err != nil {
        http.Error(w, "Error loading .env file", http.StatusInternalServerError)
        return
    }

    // Read the bot token from the environment variables
    botToken := os.Getenv("BOT_TOKEN")
    if botToken == "" {
        http.Error(w, "BOT_TOKEN not set in .env", http.StatusInternalServerError)
        return
    }

    // Read the body of the request
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Error reading request body", http.StatusInternalServerError)
        return
    }

    // Parse the body as a URL-encoded string
    values, err := url.ParseQuery(string(body))
    if err != nil {
        http.Error(w, "Error parsing request body", http.StatusInternalServerError)
        return
    }

    // Get the hash from the parsed values
    hash := values.Get("hash")
    if hash == "" {
        http.Error(w, "Hash not provided", http.StatusBadRequest)
        return
    }

    // Generate the data-check-string without trailing newline
    var dataCheckString strings.Builder
    keys := make([]string, 0, len(values))
    for key := range values {
        if key != "hash" {
            keys = append(keys, key)
        }
    }
    sort.Strings(keys)
    for i, key := range keys {
        value := values.Get(key)
        if key == "auth_date" {
            intValue, err := strconv.Atoi(value)
            if err != nil {
                http.Error(w, "Error converting auth_date to integer", http.StatusBadRequest)
                return
            }
            value = strconv.Itoa(intValue)
        }
        if key == "user" {
            // URL decode the user parameter
            value, err = url.QueryUnescape(value)
            if err != nil {
                http.Error(w, "Error decoding user parameter", http.StatusBadRequest)
                return
            }
        }
        if i > 0 {
            dataCheckString.WriteString("\n")
        }
        dataCheckString.WriteString(fmt.Sprintf("%s=%s", key, value))
    }

    // Generate the secret_key using "WebAppData" as key and botToken as message
    secretKeyHMAC := hmac.New(sha256.New, []byte("WebAppData"))
    secretKeyHMAC.Write([]byte(botToken))
    secretKey := secretKeyHMAC.Sum(nil)

    // Generate the hash of the data_check_string using the secret_key
    hashHMAC := hmac.New(sha256.New, secretKey)
    hashHMAC.Write([]byte(dataCheckString.String()))
    calculatedHash := hex.EncodeToString(hashHMAC.Sum(nil))

    // Compare the hashes
    if calculatedHash != hash {
        http.Error(w, "Invalid data", http.StatusUnauthorized)
        return
    }

    // Parse dataCheckString into a map
    dataMap := make(map[string]string)
    for _, line := range strings.Split(dataCheckString.String(), "\n") {
        parts := strings.SplitN(line, "=", 2)
        if len(parts) == 2 {
            dataMap[parts[0]] = parts[1]
        }
    }

    // Handle the nested user JSON
    var user map[string]interface{}
    if userJSON, ok := dataMap["user"]; ok {
        err := json.Unmarshal([]byte(userJSON), &user)
        if err != nil {
            http.Error(w, "Error parsing user JSON", http.StatusInternalServerError)
            return
        }
        delete(dataMap, "user")
    }

    // Convert the map to JSON
    responseMap := make(map[string]interface{})
    for k, v := range dataMap {
        if k == "auth_date" {
            intValue, err := strconv.Atoi(v)
            if err != nil {
                http.Error(w, "Error converting auth_date to integer", http.StatusBadRequest)
                return
            }
            responseMap[k] = intValue
        } else {
            responseMap[k] = v
        }
    }
    if user != nil {
        responseMap["user"] = user
    }

    responseData, err := json.Marshal(responseMap)
    if err != nil {
        http.Error(w, "Error generating JSON response", http.StatusInternalServerError)
        return
    }

    // Set the response header to application/json
    w.Header().Set("Content-Type", "application/json")
    w.Write(responseData)
}
