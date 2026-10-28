// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package httpclient

import (
	"fmt"
	"net/http"
)

// RoundTrip bounds the response body returned by the underlying transport.
func (transport *responseLimitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.transport.RoundTrip(request)
	if err != nil {
		return nil, err
	}

	if response.ContentLength > maxResponseBytes {
		_ = response.Body.Close()
		return nil, fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}

	response.Body = &limitedResponseBody{
		ReadCloser: response.Body,
		remaining:  maxResponseBytes,
	}

	return response, nil
}

// Read returns response bytes and errors if the body exceeds the configured limit.
func (body *limitedResponseBody) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}

	if body.remaining == 0 {
		var probe [1]byte
		read, err := body.ReadCloser.Read(probe[:])
		if read != 0 {
			return 0, fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
		}

		return 0, err
	}

	if int64(len(buffer)) > body.remaining {
		buffer = buffer[:body.remaining]
	}

	read, err := body.ReadCloser.Read(buffer)
	body.remaining -= int64(read)
	return read, err
}
