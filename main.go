package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/Danny-Dasilva/CycleTLS/cycletls"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"main/Request"
	"main/Response"
	"net/http"
	"os"
	"strings"
)

func main() {
	port := "8000"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	err := os.Setenv("tls13", "1")
	if err != nil {
		log.Println(err.Error())
	}

	router := mux.NewRouter()
	router.HandleFunc("/check-status", CheckStatus).Methods("GET")
	router.HandleFunc("/handle", Handle).Methods("POST")
	fmt.Println("The proxy server is running")
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func CheckStatus(responseWriter http.ResponseWriter, request *http.Request) {
	var handleResponse Response.HandleResponse
	responseWriter.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(responseWriter).Encode("good")
	if err != nil {
		ProcessException(&handleResponse, &responseWriter, err)
	}
}

func Handle(responseWriter http.ResponseWriter, request *http.Request) {
	responseWriter.Header().Set("Content-Type", "application/json")

	var handleRequest Request.HandleRequest
	var handleResponse Response.HandleResponse

	err := json.NewDecoder(request.Body).Decode(&handleRequest)
	if err != nil {
		ProcessException(&handleResponse, &responseWriter, err)
		return
	}

	client := cycletls.Init()
	resp, err := client.Do(handleRequest.Url, cycletls.Options{
		Cookies: handleRequest.Cookies,
		//InsecureSkipVerify: handleRequest.InsecureSkipVerify,
		Body:            handleRequest.Body,
		Proxy:           handleRequest.Proxy,
		Timeout:         handleRequest.Timeout,
		Headers:         handleRequest.Headers,
		Ja3:             handleRequest.Ja3,
		UserAgent:       handleRequest.UserAgent,
		DisableRedirect: handleRequest.DisableRedirect,
	}, handleRequest.Method)

	if err != nil {
		ProcessException(&handleResponse, &responseWriter, err)
		return
	}

	handleResponse.Success = true
	handleResponse.Payload = &Response.HandleResponsePayload{
		Text:    DecodeResponse(&resp),
		Headers: resp.Headers,
		Status:  resp.Status,
		Cookies: ProcessCookies(&resp),
	}

	err = json.NewEncoder(responseWriter).Encode(handleResponse)
	if err != nil {
		ProcessException(&handleResponse, &responseWriter, err)
		return
	}
}

func ProcessException(handleResponse *Response.HandleResponse, responseWriter *http.ResponseWriter, err error) {
	fmt.Println(err)
	handleResponse.Success = false
	handleResponse.Error = err.Error()
	err = json.NewEncoder(*responseWriter).Encode(handleResponse)
	if err != nil {
		handleResponse.Error = err.Error()
	}
}

func ProcessCookies(response *cycletls.Response) []*cycletls.Cookie {
	cookieStrings, ok := response.Headers["Set-Cookie"]
	if ok {
		header := http.Header{}
		header.Add("Set-Cookie", cookieStrings)
		req := http.Response{Header: header}
		httpCookies := req.Cookies()

		var cookies []*cycletls.Cookie
		for _, cookie := range httpCookies {
			cookies = append(cookies, &cycletls.Cookie{
				Name:     cookie.Name,
				Value:    cookie.Value,
				Path:     cookie.Path,
				Domain:   cookie.Domain,
				Expires:  cookie.Expires,
				MaxAge:   cookie.MaxAge,
				Secure:   cookie.Secure,
				HTTPOnly: cookie.HttpOnly,
			})
		}
		return cookies
	}
	return nil
}

func DecodeResponse(response *cycletls.Response) string {
	switch response.Headers["Content-Encoding"] {
	case "gzip":
		reader, _ := gzip.NewReader(strings.NewReader(response.Body))
		defer reader.Close()
		readerResponse, _ := ioutil.ReadAll(reader)
		return string(readerResponse)
	default:
		return response.Body
	}
}
