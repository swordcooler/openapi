package toutiao

type JsCode2SessionResponse struct {
	Openid          string `json:"openid"`
	AnonymousOpenid string `json:"anonymous_openid"`
	SessionKey      string `json:"session_key"`
	Error           int32  `json:"error"`
	Message         string `json:"message"`
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
