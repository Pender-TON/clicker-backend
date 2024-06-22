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

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	client      *mongo.Client
	db          *mongo.Database
	clicksColl  *mongo.Collection
	ctx         context.Context
	botToken    string
	mongoURI    string
	database    = "pender-clicks"
	collection  = "clicks-01"
)

func init() {
	var err error
	err = godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	mongoURI = os.Getenv("MONGODB_CONNECTION_STRING")
	botToken = os.Getenv("BOT_TOKEN")
	if botToken == "" {
		log.Fatal("BOT_TOKEN environment variable is empty")
	}

	ctx = context.Background()
	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	db = client.Database(database)
	clicksColl = db.Collection(collection)
	fmt.Println("Connected to MongoDB Atlas!")
}

type VerifyRequest struct {
	Hash string `json:"hash"`
	Data string `json:"data"`
}

type UpdateRequest struct {
	UserID   int    `json:"userId"`
	UserName string `json:"userName"`
	Count    int    `json:"count"`
}

type InitRequest struct {
	UserID   int    `json:"userId"`
	UserName string `json:"userName"`
	Count    int    `json:"count"`
}

func main() {
	router := mux.NewRouter()
	router.Use(enableCors)
	router.HandleFunc("/updateField", updateFieldHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/createDocument", createDocumentHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/getDocument", getDocumentHandler).Methods("GET", "OPTIONS")
	router.HandleFunc("/verifySignature", verifySignatureHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/dbInit", dbInitHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/getPosition", getPositionHandler).Methods("POST", "OPTIONS")

	err := http.ListenAndServeTLS(":443", "cert.pem", "key.pem", router)
	if err != nil {
		log.Fatal(err)
	}
}

func enableCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func updateFieldHandler(w http.ResponseWriter, r *http.Request) {
	var req UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	filter := bson.M{"userId": req.UserID, "userName": req.UserName}
	var currentDoc struct {
		Count int `bson:"count"`
	}
	err := clicksColl.FindOne(ctx, filter).Decode(&currentDoc)
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

	_, err = clicksColl.UpdateOne(ctx, filter, update)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, req.Count)
}

func createDocument(userId int, userName string, count int) error {
	document := bson.M{
		"userId":   userId,
		"userName": userName,
		"count":    count,
	}

	_, err := clicksColl.InsertOne(ctx, document)
	return err
}

func createDocumentHandler(w http.ResponseWriter, r *http.Request) {
	var req InitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := createDocument(req.UserID, req.UserName, req.Count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func getDocumentHandler(w http.ResponseWriter, r *http.Request) {
	opts := options.Find().SetSort(bson.D{{Key: "count", Value: -1}}).SetLimit(5)

	cursor, err := clicksColl.Find(ctx, bson.D{{}}, opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var results []bson.M
	if err = cursor.All(ctx, &results); err != nil {
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

func getPositionHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		UserId int `json:"userId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	cursor, err := clicksColl.Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "count", Value: -1}}))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var results []bson.M
	if err = cursor.All(ctx, &results); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	position := -1
	for i, result := range results {
		dbUserId, ok := result["userId"].(int32)
		if !ok {
			dbUserId64, ok := result["userId"].(int64)
			if !ok {
				fmt.Printf("Unexpected type for userId: %T\n", result["userId"])
				continue
			}
			dbUserId = int32(dbUserId64)
		}

		if dbUserId == int32(requestData.UserId) {
			position = i + 1
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"position": position})
}

func dbInitHandler(w http.ResponseWriter, r *http.Request) {
	var req InitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	filter := bson.M{
		"userId":   req.UserID,
		"userName": req.UserName,
	}

	var result struct {
		Count int `bson:"count"`
	}
	err := clicksColl.FindOne(ctx, filter).Decode(&result)
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
    // Read the raw request body
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Unable to read request body", http.StatusInternalServerError)
        return
    }

    //log.Printf("Request body: %s", body)

    // Parse the URL-encoded data
    values, err := url.ParseQuery(string(body))
    if err != nil {
        http.Error(w, "Error parsing request body", http.StatusBadRequest)
        return
    }

    // Extract the hash
    hash := values.Get("hash")
    if hash == "" {
        http.Error(w, "Hash not provided", http.StatusBadRequest)
        return
    }

    // Remove the hash from values to create the data-check-string
    values.Del("hash")

    // Generate the data-check-string
    var dataCheckString strings.Builder
    keys := make([]string, 0, len(values))
    for key := range values {
        keys = append(keys, key)
    }
    sort.Strings(keys)
    for i, key := range keys {
        if i > 0 {
            dataCheckString.WriteString("\n")
        }
        dataCheckString.WriteString(fmt.Sprintf("%s=%s", key, values.Get(key)))
    }

    // Generate the secret key using HMAC-SHA256 with the bot token
    secretKeyHMAC := hmac.New(sha256.New, []byte("WebAppData"))
    secretKeyHMAC.Write([]byte(botToken))
    secretKey := secretKeyHMAC.Sum(nil)

    // Generate the hash of the data-check-string using the secret key
    hashHMAC := hmac.New(sha256.New, secretKey)
    hashHMAC.Write([]byte(dataCheckString.String()))
    calculatedHash := hex.EncodeToString(hashHMAC.Sum(nil))

    // Compare the hashes
    if calculatedHash != hash {
        http.Error(w, "Invalid data", http.StatusUnauthorized)
        return
    }

    // Prepare the response map
    responseMap := make(map[string]interface{})
    for key := range values {
        value := values.Get(key)
        if key == "auth_date" {
            intValue, err := strconv.Atoi(value)
            if err != nil {
                http.Error(w, "Error converting auth_date to integer", http.StatusBadRequest)
                return
            }
            responseMap[key] = intValue
        } else {
            responseMap[key] = value
        }
    }

    // Handle the nested user JSON
    if userJSON, ok := responseMap["user"].(string); ok {
        var user map[string]interface{}
        err := json.Unmarshal([]byte(userJSON), &user)
        if err != nil {
            http.Error(w, "Error parsing user JSON", http.StatusInternalServerError)
            return
        }
        responseMap["user"] = user
    }

    // Convert the response map to JSON
    responseData, err := json.Marshal(responseMap)
    if err != nil {
        http.Error(w, "Error generating JSON response", http.StatusInternalServerError)
        return
    }

    // Set the response header to application/json
    w.Header().Set("Content-Type", "application/json")
    w.Write(responseData)
}