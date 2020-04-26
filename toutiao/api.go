package toutiao

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/swordcooler/openapi/common"
)

const (
	LoginURL = "https://developer.toutiao.com/api/apps/jscode2session"
)

var (
	UnifiedOrderError = errors.New("unified order error")
)

type APIProxy struct {
	config *Config
}

func NewAPIProxy(config *Config) *APIProxy {
	return &APIProxy{
		config: config,
	}
}

func (api *APIProxy) Login(code, anonymounsCode string) (*JsCode2SessionResponse, error) {
	params := make(map[string]string)
	params["appid"] = api.config.Appid
	params["secret"] = api.config.Secret
	if len(code) > 0 {
		params["code"] = code
	} else {
		params["anonymous_code"] = anonymounsCode
	}

	var response JsCode2SessionResponse
	err := common.Request(http.MethodGet, "", LoginURL, params, &response)
	return &response, err
}

func (api *APIProxy) GetUserInfo(sessionKey, rawData, signature string) (*UserInfo, error) {
	var userInfo UserInfo
	h := sha1.New()

	h.Write([]byte(fmt.Sprintf("%s%s", rawData, sessionKey)))
	sign := fmt.Sprintf("%x", h.Sum(nil))

	fmt.Print(sign)
	if sign != signature {
		fmt.Println("sign unmatch")
		//return nil, errors.New("sign unmatch")
	}

	err := json.Unmarshal([]byte(rawData), &userInfo)
	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}
