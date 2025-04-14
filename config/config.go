package config

type Config struct {
	// ... existing code ...
	SessionCookieName string `yaml:"session_cookie_name"`
	SessionMaxAge     int    `yaml:"session_max_age"`
	SessionPath       string `yaml:"session_path"`
	SessionDomain     string `yaml:"session_domain"`
	SessionSecure     bool   `yaml:"session_secure"`
	SessionHttpOnly   bool   `yaml:"session_http_only"`
	SessionSameSite   string `yaml:"session_same_site"`
	CookieConfig      string `yaml:"cookie_config"`
	CookieHashKey     string `yaml:"cookie_hash_key"`
	CookieBlockKey    string `yaml:"cookie_block_key"`
	// ... existing code ...
}
