package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

const csrfCookieName = "csrf_token"

var formTagPattern = regexp.MustCompile(`(?i)(<form\b[^>]*>)`)

func generateCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(bytes), nil
}

func getCSRFToken(c *fiber.Ctx) string {
	if cached := c.Locals("csrfToken"); cached != nil {
		if token, ok := cached.(string); ok {
			return token
		}
	}
	return strings.TrimSpace(c.Cookies(csrfCookieName))
}

func isUnsafeMethod(method string) bool {
	switch method {
	case fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete:
		return true
	default:
		return false
	}
}

func validateSameSiteHeaders(c *fiber.Ctx) error {
	host := strings.ToLower(c.Hostname())

	if origin := strings.TrimSpace(c.Get(fiber.HeaderOrigin)); origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Hostname() == "" {
			return fiber.NewError(fiber.StatusForbidden, "invalid origin")
		}
		if !strings.EqualFold(parsed.Hostname(), host) {
			return fiber.NewError(fiber.StatusForbidden, "invalid origin")
		}
		return nil
	}

	if ref := strings.TrimSpace(c.Get(fiber.HeaderReferer)); ref != "" {
		parsed, err := url.Parse(ref)
		if err != nil {
			return fiber.NewError(fiber.StatusForbidden, "invalid referer")
		}
		if parsed.Hostname() != "" && !strings.EqualFold(parsed.Hostname(), host) {
			return fiber.NewError(fiber.StatusForbidden, "invalid referer")
		}
		return nil
	}

	return fiber.NewError(fiber.StatusForbidden, "missing origin or referer")
}

func CSRFMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := getCSRFToken(c)
		if token == "" {
			generated, err := generateCSRFToken()
			if err != nil {
				return err
			}
			token = generated
			c.Locals("csrfToken", token)
			c.Cookie(&fiber.Cookie{
				Name:     csrfCookieName,
				Value:    token,
				HTTPOnly: true,
				Secure:   strings.EqualFold(c.Protocol(), "https"),
				SameSite: fiber.CookieSameSiteLaxMode,
				Expires:  time.Now().Add(24 * time.Hour),
			})
		} else {
			c.Locals("csrfToken", token)
		}

		if !isUnsafeMethod(c.Method()) {
			return c.Next()
		}

		if err := validateSameSiteHeaders(c); err != nil {
			return err
		}

		requestToken := strings.TrimSpace(c.Get("X-CSRF-Token"))
		if requestToken == "" {
			requestToken = strings.TrimSpace(c.FormValue("csrf_token"))
		}

		if requestToken == "" || subtle.ConstantTimeCompare([]byte(requestToken), []byte(token)) != 1 {
			return fiber.NewError(fiber.StatusForbidden, "invalid CSRF token")
		}

		return c.Next()
	}
}

func injectCSRFContent(body, token string) string {
	if token == "" {
		return body
	}

	body = formTagPattern.ReplaceAllString(body, `$1<input type="hidden" name="csrf_token" value="`+token+`">`)

	headInsert := `<meta name="csrf-token" content="` + token + `">` +
		`<script>(function(){var t="` + token + `";if(window.htmx&&window.htmx.config){window.htmx.config.headers=window.htmx.config.headers||{};window.htmx.config.headers["X-CSRF-Token"]=t;}})();</script>`

	if strings.Contains(body, "</head>") {
		return strings.Replace(body, "</head>", headInsert+"</head>", 1)
	}

	return body + headInsert
}

func CSRFResponseMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := c.Next(); err != nil {
			return err
		}

		contentType := string(c.Response().Header.ContentType())
		if contentType == "" {
			contentType = c.Get(fiber.HeaderContentType)
		}
		if !strings.Contains(strings.ToLower(contentType), "text/html") {
			return nil
		}

		body := c.Response().Body()
		if len(body) == 0 {
			return nil
		}

		token := getCSRFToken(c)
		if token == "" {
			return nil
		}

		updated := injectCSRFContent(string(body), token)
		c.Response().SetBody([]byte(updated))
		return nil
	}
}
