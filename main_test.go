package main

import (
	"bytes"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func setupTestApp(t *testing.T) *fiber.App {
	t.Helper()
	prevRoot := uploadRoot
	uploadRoot = t.TempDir()
	t.Cleanup(func() { uploadRoot = prevRoot })

	app := fiber.New(fiber.Config{BodyLimit: int(maxUploadSize)})
	app.Post("/upload", func(c *fiber.Ctx) error {
		fileHeader, err := c.FormFile("file")
		if err != nil {
			return err
		}
		if _, err := saveUploadedFile(c, fileHeader); err != nil {
			return err
		}
		return c.SendStatus(http.StatusCreated)
	})
	return app
}

func createMultipartRequest(t *testing.T, filename, contentType string, data []byte) *http.Request {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, filename))
	header.Set("Content-Type", contentType)

	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatalf("failed to create multipart part: %v", err)
	}

	if _, err = part.Write(data); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("failed to finalize multipart data: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestUploadRejectsUnsupportedType(t *testing.T) {
	app := setupTestApp(t)

	req := createMultipartRequest(t, "malicious.txt", "text/plain", []byte("not an image"))

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}

func TestUploadRejectsOversizedFile(t *testing.T) {
	app := setupTestApp(t)

	largePayload := bytes.Repeat([]byte("a"), int(maxUploadSize)+1)
	req := createMultipartRequest(t, "oversized.jpg", "image/jpeg", largePayload)

	resp, err := app.Test(req)
	if err != nil {
		var fe *fiber.Error
		if errors.As(err, &fe) {
			if fe.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, fe.Code)
			}
			return
		}

		if strings.Contains(err.Error(), "body size exceeds") {
			return
		}

		t.Fatalf("request failed: %v", err)
	}

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, resp.StatusCode)
	}
}
