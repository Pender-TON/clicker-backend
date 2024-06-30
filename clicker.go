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

type UserStats struct {
    AuthDate      int     `json:"auth_date" bson:"auth_date"`
    UserID        int     `json:"id" bson:"id"`
    IsPremium     bool    `json:"is_premium" bson:"is_premium"`
    LanguageCode  string  `json:"language_code" bson:"language_code"`
    UserName      string  `json:"username" bson:"username"`
    Count         int     `json:"count" bson:"count"`
    Address       string  `json:"address" bson:"address"`
    Gems          int     `json:"gems" bson:"gems"`
    Multiplier    int     `json:"multiplier" bson:"multiplier"`
    TonBalance    float64 `json:"tonBalance" bson:"tonBalance"`
}

type VerifyRequest struct {
	Hash string `json:"hash"`
	Data string `json:"data"`
}

type UpdateRequest struct {
	UserID   int    `json:"id"`
	UserName string `json:"userName"`
	Count    int    `json:"count"`
}

//type InitRequest struct {
//	UserID   int    `json:"userId"`
//	UserName string `json:"userName"`
//	Count    int    `json:"count"`
//}

func main() {
	router := mux.NewRouter()
	router.Use(enableCors)
	router.HandleFunc("/updateField", updateFieldHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/getDocument", getDocumentHandler).Methods("GET", "OPTIONS")
	router.HandleFunc("/verifySignature", verifySignatureHandler).Methods("POST", "OPTIONS")
    router.HandleFunc("/updateAddress", updateAddressHandler).Methods("POST", "OPTIONS")
	//router.HandleFunc("/dbInit", dbInitHandler).Methods("POST", "OPTIONS")
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

// Extracted logic from updateFieldHandler
func updateCount(ctx context.Context, userId int, count int) (int, error) {
    filter := bson.M{"id": userId}
    var currentDoc struct {
        Count int `bson:"count"`
    }
    err := clicksColl.FindOne(ctx, filter).Decode(&currentDoc)
    if err != nil {
        return 0, err // Simplified error handling for demonstration
    }

    if count <= currentDoc.Count {
        return currentDoc.Count, nil
    }

    update := bson.M{"$set": bson.M{
        "count": count,
    }}

    _, err = clicksColl.UpdateOne(ctx, filter, update)
    if err != nil {
        return 0, err
    }

    return count, nil
}

// Function to update the address field in the database
func updateAddress(ctx context.Context, userId int, address string) (int, error) {
    
    type ApiResponse struct {
        NftItems []struct {
            Collection struct {
                Address string `json:"address"`
            } `json:"collection"`
        } `json:"nft_items"`
    }
    filter := bson.M{"id": userId}
    var currentDoc struct {
        Address string `bson:"address"`
        Multiplier int `bson:"multiplier"`
    }
    if address == "" {
        update := bson.M{"$set": bson.M{
            "address": address,
            "multiplier": 1,
        }}
        _, err := clicksColl.UpdateOne(ctx, filter, update)
        if err != nil {
            return 0, err
        }
        return 1, nil // Return the current multiplier value
    }
    
    url := fmt.Sprintf("https://tonapi.io/v2/accounts/%s/nfts", address)
    resp, err := http.Get(url)
    if err != nil {
        return 0, fmt.Errorf("error validating address: %w", err)
    }
    //defer resp.Body.Close()

    // Check if the address is valid based on the response status code
    if resp.StatusCode != http.StatusOK {
        return 0, fmt.Errorf("invalid address, received status code: %d", resp.StatusCode)
    }
    
    var apiResp ApiResponse
    err = json.NewDecoder(resp.Body).Decode(&apiResp)
    if err != nil {
        return 0, fmt.Errorf("error decoding response: %w", err)
    }
    resp.Body.Close()
    //fmt.Println(apiResp)

    found := false
    for _, item := range apiResp.NftItems {
        if item.Collection.Address == "0:182fed439ab4db02a71ac0bf28cab653fde7ebd380946a351cdf4f613f1f5d45" {
            found = true
            break
        }
    }

    err = clicksColl.FindOne(ctx, filter).Decode(&currentDoc)
    if err != nil {
        return 0, err
    }
    if found {
        // If a matching NFT is found, set multiplier to 2 along with updating the address
        update := bson.M{"$set": bson.M{
            "address": address,
            "multiplier": 5,
        }}
        _, err = clicksColl.UpdateOne(ctx, filter, update)
        if err != nil {
            return 0, err
        }
        return currentDoc.Multiplier, nil // Return 2 as the new multiplier value
    } else {
        // If no matching NFT is found, only update the address
        update := bson.M{"$set": bson.M{
            "address": address,
            "multiplier": 2,
        }}
        _, err = clicksColl.UpdateOne(ctx, filter, update)
        if err != nil {
            return 0, err
        }
        return currentDoc.Multiplier, nil // Return the current multiplier value
    }

}

// Handler for updating the address
func updateAddressHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        UserID  int    `json:"id"`
        Address string `json:"address"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Context from the request, or background if not available
    ctx := r.Context()

    mult, err := updateAddress(ctx, req.UserID, req.Address)
    if err != nil {
        // Handle error, possibly with different messages based on the error type
        http.Error(w, "Failed to update address", http.StatusInternalServerError)
        return
    }
    response := struct {
        Multiplier int `json:"multiplier"`
    }{
        Multiplier: mult,
    }

    jsonResponse, err := json.Marshal(response)
    if err != nil {
        http.Error(w, "Failed to encode response", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write(jsonResponse)
}

func updateFieldHandler(w http.ResponseWriter, r *http.Request) {
    var req UpdateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

	updatedCount, err := updateCount(ctx, req.UserID, req.Count)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            http.Error(w, "No document found with the provided userId and userName", http.StatusNotFound)
        } else {
            http.Error(w, err.Error(), http.StatusInternalServerError)
        }
        return
    }

    fmt.Fprint(w, updatedCount)
}

func createDocument(UserStats UserStats) error {
    // Initialize document with zero-values for all fields
    document := bson.M{
        "id":             UserStats.UserID,
        "userName":       UserStats.UserName,
        "count":          UserStats.Count,
        "is_premium":     UserStats.IsPremium,
        "language_code":  UserStats.LanguageCode,
        "address":        UserStats.Address,
        "gems":           UserStats.Gems,
        "multiplier":     1,
        "tonBalance":     UserStats.TonBalance,
    }

    result, err := clicksColl.InsertOne(ctx, document)
    if err != nil {
        log.Printf("Failed to create new document: %v\n", err)
        return err
    }

    log.Printf("New document created with ID: %+v\n", result)
    return nil
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
		UserId int `json:"id"`
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
		dbUserId, ok := result["id"].(int32)
		if !ok {
			dbUserId64, ok := result["id"].(int64)
			if !ok {
				fmt.Printf("Unexpected type for id: %T\n", result["id"])
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
// Assuming clicksColl is your MongoDB collection and ctx is your context
func dbInit(ctx context.Context, userId int) (UserStats, error) {
    filter := bson.M{"id": userId}
    var result UserStats // Initialize an empty UserStats struct to hold the result

    err := clicksColl.FindOne(ctx, filter).Decode(&result)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            // Handle the case where no document is found
            return UserStats{}, mongo.ErrNoDocuments
        }
        // Handle other potential errors
        return UserStats{}, err
    }

    // If the document was found and successfully decoded, return the result and nil for the error
    return result, nil
}

func verifySignatureHandler(w http.ResponseWriter, r *http.Request) {
    // Read the raw request body
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Unable to read request body", http.StatusInternalServerError)
        return
    }

    log.Printf("Request body: %s", body)

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
    var user UserStats
    var tempUser UserStats
    responseMap := make(map[string]interface{})
    for key := range values {
        if key == "chat_instance" || key == "chat_type" {
            continue
        }
        value := values.Get(key)
        if key == "auth_date" {
            intValue, err := strconv.Atoi(value)
            if err != nil {
                http.Error(w, "Error converting auth_date to integer", http.StatusBadRequest)
                return
            }
            responseMap[key] = intValue
            user.AuthDate = intValue
        } else {
            responseMap[key] = value
        }
    }

    // Handle the nested user JSON
    if userJSON, ok := responseMap["user"].(string); ok {
        if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
            http.Error(w, "Error parsing user JSON", http.StatusInternalServerError)
            return
        }
    }

    
    
    // Log the body content
    //log.Printf("Request body before dbInit: %s\n", string(bodyBytes))
    if user.UserID == 0 {
        log.Printf("Error: UserID is nil\n")
        http.Error(w, "UserID is required", http.StatusBadRequest)
        return
    }
    tempUser, err = dbInit(r.Context(), user.UserID)
    if err != nil {
        log.Printf("Creating new doc: %v\n", err) // Log the actual error
        createDocument(user)
        //http.Error(w, "Error updating count", http.StatusInternalServerError)
        //return
    } else {
        user = tempUser
    }


    jsonUser, err := json.Marshal(user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Set the response header to application/json
    w.Header().Set("Content-Type", "application/json")
    w.Write(jsonUser)
}