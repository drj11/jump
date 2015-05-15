package main

import (
	"io/ioutil"
	"net/http"
)

func Metadata(path string) (string, error) {
	resp, err := http.Get("http://169.254.169.254/latest/meta-data/" + path)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func ThisRegion() (string, error) {
	result, err := Metadata("placement/availability-zone")
	if err == nil {
		result = result[:len(result)-1]
	}
	return result, err
}
