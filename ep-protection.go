package avantsecure

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
)

func EndpointProtection(privateAPIKey string) gin.HandlerFunc {

	return func(c *gin.Context) {
		cookie, err := c.Request.Cookie("avant")
		if err == http.ErrNoCookie {
			respondWithError(c, 400, "untrusted")
			return
		}
		cookieAuth := verify(cookie.Value, privateAPIKey)
		if cookieAuth.status == "internal error" {
			respondWithError(c, 500, "internal error")
			return
		} else if cookieAuth.status == "deny" {
			respondWithError(c, 400, "untrustes")
		}
		c.Next()
	}
}

func verify(cookie string, apiKey string) struct {
	status string
	reason string
} {

	url := "http://avantsecure.net/endpointprotection/" + cookie
	method := "GET"

	client := &http.Client{}

	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return verifyResponse("deny", "internal error")
	}

	req.Header.Add("x-api-key", apiKey)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return verifyResponse("internal error", "")
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return verifyResponse("internal error", "")
	}

	var avantResponse cookieRes
	err = json.Unmarshal([]byte(body), &avantResponse) // here!

	if err != nil {
		return verifyResponse("internal error", "")
	}

	// fmt.Println(string(body))
	// fmt.Println(res.Body)
	if avantResponse.Status != "allow" {
		return verifyResponse("deny", avantResponse.Reason)
	} else {
		return verifyResponse("allow", "")
	}
}

func verifyResponse(status string, reason string) struct {
	status string
	reason string
} {
	return struct {
		status string
		reason string
	}{
		status: status, reason: reason,
	}
}

func respondWithError(c *gin.Context, code int, message interface{}) {
	c.AbortWithStatusJSON(code, gin.H{"status": message})
}

type cookieRes struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}
