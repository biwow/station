package output

import "strconv"

func ParamToInt(s interface{}) int {
	if s == nil {
		return 0
	}
	switch s.(type) {
	case string:
		res, _ := strconv.Atoi(s.(string))
		return res
	case float64:
		return int(s.(float64))
	}
	return 0
}

func ParamToInt32(s interface{}) int32 {
	if s == nil {
		return 0
	}
	switch s.(type) {
	case string:
		res, _ := strconv.Atoi(s.(string))
		return int32(res)
	case float64:
		return int32(s.(float64))
	}
	return 0
}

func ParamToString(s interface{}) string {
	if s == nil {
		return ""
	}
	switch s.(type) {
	case string:
		return s.(string)
	case float64:
		res := int(s.(float64))
		return strconv.Itoa(res)
	}
	return ""
}
func ParamToFloat64(s interface{}) float64 {
	if s == nil {
		return 0
	}
	switch s.(type) {
	case string:
		v, err := strconv.ParseFloat(s.(string), 32)
		if err != nil {
			v = 0
		}
		return v
	case float64:
		return s.(float64)
	}
	return 0
}
