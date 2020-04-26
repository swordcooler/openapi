package common

import (
	"fmt"
	"testing"
)

func TestGenerateSign(t *testing.T) {
	params := make(map[string]string)
	params["appId"] = "wxd678efh567hg6787"
	params["nonceStr"] = "5K8264ILTKCH16CQ2502SI8ZNMTM67VS"
	params["package"] = "prepay_id=wx2017033010242291fcfe0db70013231072"
	params["signType"] = "MD5"
	params["timeStamp"] = "1490840662"

	sign := GenerateSign("qazwsxedcrfvtgbyhnujmikolp111111", params)

	fmt.Println("sign ", sign)

	params2 := make(map[string]string)
	params2["appid"] = "wxd930ea5d5a258f4f"
	params2["mch_id"] = "10000100"
	params2["device_info"] = "1000"
	params2["body"] = "test"
	params2["nonce_str"] = "ibuaiVcKdpRxkhJA"

	sign2 := GenerateSign("192006250b4c09247ec02edce69f6a2d", params2)

	fmt.Println("sign2 ", sign2)

}
