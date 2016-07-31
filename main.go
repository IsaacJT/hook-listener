package main;

import (
  "fmt"
  "strings"
  "net/http"
  "crypto/hmac"
)
// checkMAC reports whether messageMAC is a valid HMAC tag for message.
func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func handler(w http.ResponseWriter, r *http.Request) {
  if (r.Method != "POST") {
    w.WriteHeader(http.StatusMethodNotAllowed)
    return
  }
  if (checkMAC([]byte(r.Body),
               []byte(strings.Split(r.Header.Get("X-Hub-Signature"), "=")[1]),
               []byte("test"))) {
    w.WriteHeader(http.StatusOK)
  } else {
    w.WriteHeader(http.StatusUnauthorized)
  }
}

func main() {
  http.HandleFunc("/", handler)
  http.ListenAndServe("127.0.0.1:13000", nil)
}
