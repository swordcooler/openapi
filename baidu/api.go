package baidu

import (
	"encoding/json"
	"net/http"

	"github.com/swordcooler/openapi/common"
)

const (
	GetSessionKeyByCodeURL = "https://openapi.baidu.com/nalogin/getSessionKeyByCode"
)

type APIProxy struct {
	config *Config
}

func NewAPIProxy(config *Config) *APIProxy {
	return &APIProxy{
		config: config,
	}
}

type GetSessionKeyByCodeResponse struct {
	Openid           string `json:"openid"`
	SessionKey       string `json:"session_key"`
	Error            int64  `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (api *APIProxy) GetSessionKeyByCode(code string) (*GetSessionKeyByCodeResponse, error) {
	params := make(map[string]string)
	params["client_id"] = api.config.Appid
	params["sk"] = api.config.Secret
	params["code"] = code

	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	var response GetSessionKeyByCodeResponse
	err = common.Request(http.MethodPost, string(body), GetSessionKeyByCodeURL, nil, &response)
	return &response, err
}
