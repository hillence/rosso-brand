package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func newTestApp() *fiber.App {
	app := fiber.New()
	app.Use(CSRFMiddleware())
	app.Use(CSRFResponseMiddleware())

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("<html><head></head><body><form method=\"post\" action=\"/protected\"></form></body></html>")
	})

	app.Post("/protected", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	return app
}

func TestCSRFMiddlewareRejectsMissingToken(t *testing.T) {
	app := newTestApp()

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "http://example.com")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("expected %d status, got %d", fiber.StatusForbidden, resp.StatusCode)
	}
}

func TestCSRFMiddlewareRejectsInvalidOrigin(t *testing.T) {
	app := newTestApp()

	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getReq.Host = "example.com"
	getResp, err := app.Test(getReq)
	if err != nil {
		t.Fatalf("failed to fetch token: %v", err)
	}

	var csrfCookie *http.Cookie
	for _, c := range getResp.Cookies() {
		if c.Name == csrfCookieName {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatalf("expected csrf cookie to be set")
	}

	form := url.Values{}
	form.Set("csrf_token", csrfCookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(form.Encode()))
	req.Host = "example.com"
	req.Header.Set("Origin", "http://malicious.test")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("expected %d status, got %d", fiber.StatusForbidden, resp.StatusCode)
	}
}

func TestCSRFMiddlewareAllowsValidToken(t *testing.T) {
	app := newTestApp()

	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getReq.Host = "example.com"
	getResp, err := app.Test(getReq)
	if err != nil {
		t.Fatalf("failed to fetch token: %v", err)
	}

	var csrfCookie *http.Cookie
	for _, c := range getResp.Cookies() {
		if c.Name == csrfCookieName {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatalf("expected csrf cookie to be set")
	}

	form := url.Values{}
	form.Set("csrf_token", csrfCookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(form.Encode()))
	req.Host = "example.com"
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected %d status, got %d", fiber.StatusOK, resp.StatusCode)
	}
}
