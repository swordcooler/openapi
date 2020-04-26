package weixin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/swordcooler/openapi/common"
)

const (
	LoginURL                  = "https://api.weixin.qq.com/sns/jscode2session"
	OrderURL                  = "https://api.mch.weixin.qq.com/pay/unifiedorder"
	GetTokenURL               = "https://api.weixin.qq.com/cgi-bin/token"
	SetUserStorgeURL          = "https://api.weixin.qq.com/wxa/set_user_storage"
	MidasGetBalanceURL        = "https://api.weixin.qq.com/cgi-bin/midas/getbalance"
	MidasGetBalanceSandboxURL = "https://api.weixin.qq.com/cgi-bin/midas/sandbox/getbalance"
	MidasPayURL               = "https://api.weixin.qq.com/cgi-bin/midas/pay"
	MidasPaySandboxURL        = "https://api.weixin.qq.com/cgi-bin/midas/sandbox/pay"
	MidasPresentURL           = "https://api.weixin.qq.com/cgi-bin/midas/present"
	MidasPresentSandboxURL    = "https://api.weixin.qq.com/cgi-bin/midas/sandbox/present"
	MidasCannelPayURL         = "https://api.weixin.qq.com/cgi-bin/midas/cancelpay"
	MidasCannelPaySandboxURL  = "https://api.weixin.qq.com/cgi-bin/midas/sandbox/cancelpay"
	GetWXACodeUnlimitURL      = "https://api.weixin.qq.com/wxa/getwxacodeunlimit"
	SendMessageURL            = "https://api.weixin.qq.com/cgi-bin/message/custom/send"
	UploadTempMediaURL        = "https://api.weixin.qq.com/cgi-bin/media/upload"
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

func (api *APIProxy) Login(jsCode string) (*JsCode2SessionResponse, error) {
	params := make(map[string]string)
	params["appid"] = api.config.Appid
	params["secret"] = api.config.Secret
	params["js_code"] = jsCode
	params["grant_type"] = "authorization_code"

	var response JsCode2SessionResponse
	err := common.Request(http.MethodGet, "", LoginURL, params, &response)
	return &response, err
}

func (api *APIProxy) GetUserInfo(sessionKey, rawData, signature string) (*UserInfo, error) {
	var userInfo UserInfo
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%s%s", rawData, sessionKey)))
	sign := fmt.Sprintf("%x", h.Sum(nil))
	if sign != signature {
		return nil, errors.New("sign unmatch")
	}

	err := json.Unmarshal([]byte(rawData), &userInfo)
	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func (api *APIProxy) GetFullUserInfo(sessionKey, encryptData, iv string) (*UserInfo, error) {
	decodeBytes, err := base64.StdEncoding.DecodeString(encryptData)
	if err != nil {
		return nil, err
	}
	sessionKeyBytes, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		return nil, err
	}
	ivBytes, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}
	dataBytes, err := AesDecrypt(decodeBytes, sessionKeyBytes, ivBytes)

	var userInfo UserInfo
	err = json.Unmarshal(dataBytes, &userInfo)
	if err != nil {
		return nil, err
	}

	appid := userInfo.Watermark.Appid
	if appid != api.config.Appid {
		return nil, fmt.Errorf("invalid appid, get !%s!", appid)
	}
	if err != nil {
		return nil, err
	}
	return &userInfo, nil

}

func AesDecrypt(crypted, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	//获取的数据尾端有'/x0e'占位符,去除它
	for i, ch := range origData {
		if ch == '\x0e' {
			origData[i] = ' '
		}
	}
	//{"phoneNumber":"15082726017","purePhoneNumber":"15082726017","countryCode":"86","watermark":{"timestamp":1539657521,"appid":"wx4c6c3ed14736228c"}}//<nil>
	return origData, nil
}

func (api *APIProxy) UnifiedOrder(openid, tradeNo, body, totalFee, ipaddr string) (*PaymentRequest, error) {
	params := make(map[string]string)
	params["appid"] = api.config.Appid
	params["mch_id"] = api.config.MchID
	params["nonce_str"] = common.RandomString(32)
	params["body"] = body
	params["out_trade_no"] = tradeNo
	params["total_fee"] = totalFee
	params["spbill_create_ip"] = ipaddr
	params["notify_url"] = api.config.Notify
	params["trade_type"] = api.config.TradeType
	params["openid"] = openid
	params["sign_type"] = "MD5"
	params["sign"] = common.GenerateSign(api.config.Secret, params)

	var response UnifiedOrderResponse
	var request PaymentRequest

	err := common.Request(http.MethodGet, "", OrderURL, params, response)
	if response.ReturnCode == "SUCCESS" &&
		response.ResultCode == "SUCCESS" &&
		len(response.PrePayID) > 0 {
		requsetParams := make(map[string]string)
		requsetParams["appId"] = api.config.Appid
		requsetParams["timeStamp"] = strconv.Itoa(int(time.Now().Unix()))
		requsetParams["nonceStr"] = response.NonceStr
		requsetParams["signType"] = "MD5"
		requsetParams["package"] = fmt.Sprintf("prepay_id=%s", response.PrePayID)
		paySign := common.GenerateSign(api.config.Secret, requsetParams)

		request = PaymentRequest{
			TimeStamp: requsetParams["timeStamp"],
			NonceStr:  requsetParams["nonceStr"],
			Package:   requsetParams["package"],
			SignType:  requsetParams["signType"],
			PaySign:   paySign,
		}
	} else {
		err = UnifiedOrderError
	}
	return &request, err
}

func (api APIProxy) GetToken() (*GetTokenResponse, error) {
	params := make(map[string]string)
	params["appid"] = api.config.Appid
	params["secret"] = api.config.Secret
	params["grant_type"] = "client_credential"

	var response GetTokenResponse
	err := common.Request(http.MethodGet, "", GetTokenURL, params, &response)
	return &response, err
}

func (api APIProxy) SetUserStorge(openid, accessToken, sessionKey string, kvList string) (*SetUserStorgeResponse, error) {
	params := make(map[string]string)
	params["appid"] = api.config.Appid
	params["openid"] = openid
	params["access_token"] = accessToken
	params["signature"] = common.GenerateLoginStatusSign(kvList, sessionKey)
	params["sig_method"] = "hmac_sha256"

	var response SetUserStorgeResponse

	err := common.Request(http.MethodPost, kvList, SetUserStorgeURL, params, &response)
	return &response, err
}

func (api APIProxy) MidasGetBalance(openid, accessToken, pf string, isSanbox bool) (*MidasGetBalanceResponse, error) {
	requestURL := MidasGetBalanceURL
	if isSanbox {
		requestURL = MidasGetBalanceSandboxURL
	}

	urlFields, err := url.Parse(requestURL)
	if err != nil {
		return nil, err
	}

	params := make(map[string]string)
	params["access_token"] = accessToken

	calParams := make(map[string]interface{})
	calParams["openid"] = openid
	calParams["appid"] = api.config.Appid
	calParams["offer_id"] = api.config.MidasOfferID
	calParams["ts"] = time.Now().Unix()
	calParams["zone_id"] = "1"
	calParams["pf"] = pf
	calParams["sig"] = common.GenerateMidasSign(api.config.MidasSecret, urlFields.Path, calParams)
	calParams["access_token"] = accessToken
	calParams["mp_sig"] = common.GenerateMidasSign(api.config.MidasSecret, urlFields.Path, calParams)

	body, err := json.Marshal(calParams)
	if err != nil {
		return nil, err
	}

	var response MidasGetBalanceResponse

	err = common.Request(http.MethodPost, string(body), requestURL, params, &response)
	return &response, err

}

func (api *APIProxy) MidasPay(openid, accessToken, pf, billno string, amt int32, isSanbox bool) (*MidasPayResponse, error) {
	requestURL := MidasPayURL
	if isSanbox {
		requestURL = MidasPaySandboxURL
	}

	urlFields, err := url.Parse(requestURL)
	if err != nil {
		return nil, err
	}

	params := make(map[string]string)
	params["access_token"] = accessToken

	calParams := make(map[string]interface{})
	calParams["openid"] = openid
	calParams["appid"] = api.config.Appid
	calParams["offer_id"] = api.config.MidasOfferID
	calParams["ts"] = time.Now().Unix()
	calParams["zone_id"] = "1"
	calParams["amt"] = amt
	calParams["bill_no"] = billno
	calParams["pf"] = pf
	calParams["sig"] = common.GenerateMidasSign(api.config.MidasSecret, urlFields.Path, calParams)
	calParams["access_token"] = accessToken
	calParams["mp_sig"] = common.GenerateMidasSign(api.config.MidasSecret, urlFields.Path, calParams)

	body, err := json.Marshal(calParams)
	if err != nil {
		return nil, err
	}

	var response MidasPayResponse

	err = common.Request(http.MethodPost, string(body), requestURL, params, &response)
	return &response, err

}

func (api *APIProxy) MidasPresent(openid, accessToken, pf, billno string, presentCount int32, isSanbox bool) (*MidasPresentResponse, error) {
	requestURL := MidasPresentURL
	if isSanbox {
		requestURL = MidasPresentSandboxURL
	}

	urlFields, err := url.Parse(requestURL)
	if err != nil {
		return nil, err
	}

	params := make(map[string]string)
	params["access_token"] = accessToken

	calParams := make(map[string]interface{})
	calParams["openid"] = openid
	calParams["appid"] = api.config.Appid
	calParams["offer_id"] = api.config.MidasOfferID
	calParams["ts"] = time.Now().Unix()
	calParams["zone_id"] = "1"
	calParams["bill_no"] = billno
	calParams["present_counts"] = presentCount
	calParams["pf"] = pf
	calParams["sig"] = common.GenerateMidasSign(api.config.MidasSecret, urlFields.Path, calParams)
	calParams["access_token"] = accessToken
	calParams["mp_sig"] = common.GenerateMidasSign(api.config.MidasSecret, urlFields.Path, calParams)

	body, err := json.Marshal(calParams)
	if err != nil {
		return nil, err
	}

	var response MidasPresentResponse

	err = common.Request(http.MethodPost, string(body), requestURL, params, &response)
	return &response, err

}

func (api *APIProxy) MidasCannelPay(openid, accessToken, pf, billno string, isSanbox bool) (*MidasCannelPayResponse, error) {
	requestURL := MidasPresentURL
	if isSanbox {
		requestURL = MidasPresentSandboxURL
	}

	urlFields, err := url.Parse(requestURL)
	if err != nil {
		return nil, err
	}

	params := make(map[string]string)
	params["access_token"] = accessToken

	calParams := make(map[string]interface{})
	calParams["openid"] = openid
	calParams["appid"] = api.config.Appid
	calParams["offer_id"] = api.config.MidasOfferID
	calParams["ts"] = time.Now().Unix()
	calParams["zone_id"] = "1"
	calParams["bill_no"] = billno
	calParams["pf"] = pf
	calParams["sig"] = common.GenerateMidasSign(api.config.MidasSecret, urlFields.Path, calParams)
	calParams["access_token"] = accessToken
	calParams["mp_sig"] = common.GenerateMidasSign(api.config.MidasSecret, urlFields.Path, calParams)

	body, err := json.Marshal(calParams)
	if err != nil {
		return nil, err
	}

	var response MidasCannelPayResponse

	err = common.Request(http.MethodPost, string(body), requestURL, params, &response)
	return &response, err

}

func (api *APIProxy) GetWXACodeUnlimit(accessToken, scence string) (string, error) {
	requestURL := GetWXACodeUnlimitURL

	params := make(map[string]string)
	params["access_token"] = accessToken

	calParams := make(map[string]interface{})
	// calParams["access_token"] = accessToken
	calParams["scene"] = scence
	calParams["width"] = 280

	reqBody, err := json.Marshal(calParams)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}

	requsetBody := bytes.NewReader(reqBody)
	req, err := http.NewRequest(http.MethodPost, requestURL, requsetBody)
	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, v)
	}

	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	json.Unmarshal([]byte(body), &result)
	fmt.Println(result)
	if code, ok := result["errcode"]; ok && code != 0 {
		return "", errors.New(result["errmsg"].(string))
	}

	return string(body), err

}

func (api *APIProxy) SendMessage(openid, accessToken, msgType string, object interface{}) (*SendMessageResponse, error) {
	requestURL := SendMessageURL

	params := make(map[string]string)
	params["access_token"] = accessToken

	calParams := make(map[string]interface{})
	calParams["touser"] = openid
	calParams["msgtype"] = msgType
	calParams["access_token"] = accessToken

	switch msgType {
	case "text":
		calParams["text"] = object
	case "image":
		calParams["image"] = object
	case "link":
		calParams["link"] = object
	case "miniprogrampage":
		calParams["miniprogrampage"] = object
	}

	fmt.Print(calParams)

	body, err := json.Marshal(calParams)
	if err != nil {
		return nil, err
	}

	var response SendMessageResponse

	err = common.Request(http.MethodPost, string(body), requestURL, params, &response)
	return &response, err

}

func (api *APIProxy) UploadTempMidia(accessToken, mType string, f *os.File) (*UploadTempMediaResponse, error) {
	requestURL := UploadTempMediaURL

	params := make(map[string]string)
	params["access_token"] = accessToken
	params["type"] = mType

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fw, err := w.CreateFormFile("image", f.Name())
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(fw, f); err != nil {
		return nil, err
	}

	w.Close()

	req, err := http.NewRequest(http.MethodPost, requestURL, &b)
	req.Header.Set("Content-Type", w.FormDataContentType())

	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, v)
	}

	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response UploadTempMediaResponse

	json.Unmarshal([]byte(body), &response)
	return &response, nil
}
