package common

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"
)

const letterBytes = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func RandomString(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func GenerateSign(secret string, params map[string]string) string {
	paramList := make([]string, 0)
	for k, _ := range params {
		paramList = append(paramList, k)
	}

	sort.Strings(paramList)

	var paramStr string
	for _, v := range paramList {
		paramStr += fmt.Sprintf("%s=%s&", v, params[v])
	}

	stringSignTemp := fmt.Sprintf("%skey=%s", paramStr, secret)
	h := md5.New()
	io.WriteString(h, stringSignTemp)
	sign := fmt.Sprintf("%x", h.Sum(nil))

	sign = strings.ToUpper(sign)
	return sign
}

func GenerateLoginStatusSign(postData, sessionKey string) string {
	mac := hmac.New(sha256.New, []byte(sessionKey))
	mac.Write([]byte(postData))

	return fmt.Sprintf("%x", mac.Sum(nil))
}

func GenerateMidasSign(secret, path string, params map[string]interface{}) string {
	paramList := make([]string, 0)
	for k, _ := range params {
		paramList = append(paramList, k)
	}

	sort.Strings(paramList)

	var paramStr string
	for _, v := range paramList {
		paramStr += fmt.Sprintf("%s=%v&", v, params[v])
	}
	stringSignTemp := fmt.Sprintf("%sorg_loc=%s&method=POST&secret=%s", paramStr, path, secret)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringSignTemp))

	return fmt.Sprintf("%x", mac.Sum(nil))

}

var NoSupportMethod = errors.New("nonsupport method")

func Request(method, requestBody, requestURL string, params map[string]string, result interface{}) error {
	var req *http.Request
	var err error
	if method == http.MethodGet {
		req, err = http.NewRequest(http.MethodGet, requestURL, nil)
	} else if method == http.MethodPost {
		requsetBody := bytes.NewReader([]byte(requestBody))
		req, err = http.NewRequest(http.MethodPost, requestURL, requsetBody)
	} else {
		return NoSupportMethod
	}

	if err != nil {
		return err
	}

	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, v)
	}

	req.URL.RawQuery = q.Encode()

	log.Println(req.URL.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	json.Unmarshal([]byte(body), result)

	return nil
}
