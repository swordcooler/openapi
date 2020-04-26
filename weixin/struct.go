package weixin

type JsCode2SessionResponse struct {
	Openid     string `json:"openid"`
	SessionKey string `json:"session_key"`
	Unionid    string `json:"unionid"`
	ErrorCode  int32  `json:"errorcode"`
	ErrMsg     string `json:"errmsg"`
}

type UnifiedOrderResponse struct {
	ReturnCode string `json:"return_code"`
	ReturnMsg  string `json:"return_msg"`
	DeviceInfo string `json:"device_info"`
	Appid      string `json:"appid"`
	MchID      string `json:"mch_id"`
	NonceStr   string `json:"nonce_str"`
	Sign       string `json:"sign"`
	ResultCode string `json:"result_code"`
	ErrCode    string `json:"err_code"`
	ErrCodeDes string `json:"err_code_des"`
	TradeType  string `json:"trade_type"`
	PrePayID   string `json:"prepay_id"`
	CodeUrl    string `json:"code_url"`
}

type PaymentRequest struct {
	TimeStamp string
	NonceStr  string
	Package   string
	SignType  string
	PaySign   string
}

type NotifyRequest struct {
	ReturnCode         string `json:"return_code"`
	ReturnMsg          string `json:"return_msg"`
	Appid              string `json:"appid"`
	MchID              string `json:"mch_id"`
	DeviceInfo         string `json:"device_info"`
	NonceStr           string `json:"nonce_str"`
	Sign               string `json:"sign"`
	SignType           string `json:"sign_type"`
	ResultCode         string `json:"result_code"`
	ErrCode            string `json:"err_code"`
	ErrCodeDes         string `json:"err_code_des"`
	Openid             string `json:"openid"`
	IsSubscribe        string `json:"is_subscribe"`
	TradeType          string `json:"trade_type"`
	BankType           string `json:"bank_type"`
	TotalFee           int32  `json:"total_fee"`
	SettlementTotalFee int32  `json:"settlement_total_fee"`
	FeeType            string `json:"fee_type"`
	CashFee            int32  `json:"cash_fee"`
	CashFeeType        string `json:"cash_fee_type"`
	TransactionID      string `json:"transaction_id"`
	OutTradeNo         string `json:"out_trade_no"`
	Attach             string `json:"attach"`
	TimeEnd            string `json:"time_end"`
}

type GetTokenResponse struct {
	Errcode     int32  `json:"errcode"`
	Errmsg      string `json:"errmsg"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int32  `json:"expires_in"`
}

type SetUserStorgeResponse struct {
	Errcode int32  `json:"errcode"`
	Errmsg  string `json:"errmsg"`
}

type MidasGetBalanceResponse struct {
	Errcode    int32  `json:"errcode"`
	Errmsg     string `json:"errmsg"`
	Balance    int32  `json:"balance"`
	GenBalance int32  `json:"gen_balance"`
	FirstSave  bool   `json:"first_save"`
	SaveAmt    int32  `json:"save_amt"`
	SaveSum    int32  `json:"save_sum"`
	CostSum    int32  `json:"cost_sum"`
	PresentSum int32  `json:"present_sum"`
}

type MidasPayResponse struct {
	Errcode        int32  `json:"errcode"`
	Errmsg         string `json:"errmsg"`
	Balance        int32  `json:"balance"`
	BillNo         string `json:"bill_no"`
	UsedGenBalance int32  `json:"used_gen_balance"`
}

type MidasPresentResponse struct {
	Errcode int32  `json:"errcode"`
	Errmsg  string `json:"errmsg"`
	Balance int32  `json:"balance"`
	BillNo  string `json:"bill_no"`
}

type MidasCannelPayResponse struct {
	Errcode int32  `json:"errcode"`
	Errmsg  string `json:"errmsg"`
	BillNo  string `json:"bill_no"`
}

type UserInfo struct {
	Openid    string `json:"openid"`
	UnionId   string `json:"unionId"`
	NickName  string `json:"nickName"`
	Gender    int32  `json:"gender"`
	Language  string `json:"language"`
	City      string `json:"city"`
	Province  string `json:"province"`
	Country   string `json:“country”`
	AvatarUrl string `json:"avatarUrl"`
	Watermark struct {
		Appid     string `json:"appid"`
		Timestamp int64  `json:"timestamp"`
	} `json:"watermark"`
}

type SendMessageResponse struct {
	Errcode int32  `json:"errcode"`
	Errmsg  string `json:"errmsg"`
}

type UploadTempMediaResponse struct {
	Errcode   int32  `json:"errcode"`
	Errmsg    string `json:"errmsg"`
	Type      string `json:"type"`
	MediaId   string `json:"media_id"`
	CreatedAt int64  `json:"created_at"`
}
