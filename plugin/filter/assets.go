package filter

import (
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.uber.org/zap"
)

// handleAssets serves static assets for OAuth UI
func (f *Filter) handleAssets(header api.RequestHeaderMap) api.StatusType {
	traceID := f.getTraceID(header)
	path, _ := header.Get(":path")

	f.logger.Debug("Handling asset request",
		zap.String("trace_id", traceID),
		zap.String("path", path))

	// Route to appropriate asset handler
	switch {
	case strings.HasSuffix(path, "/sso.js"):
		return f.serveSSOScript(header)
	default:
		return f.handleAuthFailure(404, "Not Found: Unknown asset")
	}
}

// serveSSOScript serves the SSO JavaScript file
func (f *Filter) serveSSOScript(header api.RequestHeaderMap) api.StatusType {
	// Set response headers
	header.Set(":status", "200")
	header.Set("content-type", "application/javascript; charset=utf-8")
	header.Set("cache-control", "public, max-age=3600")

	// Send the JavaScript content
	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		200,
		getSSOScript(),
		map[string][]string{
			"content-type":  {"application/javascript; charset=utf-8"},
			"cache-control": {"public, max-age=3600"},
		},
		-1,
		"",
	)

	return api.LocalReply
}

// getSSOScript returns the SSO JavaScript content
func getSSOScript() string {
	return `(function() {
    'use strict';

    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initSSO);
    } else if (document.body) {
        initSSO();
    } else {
        // If body is not yet available, wait for it
        window.addEventListener('load', initSSO);
    }

    function initSSO() {
        let container = document.getElementById('sso-menu');
        let isAbsolute = false;

        // If no container found, create one in absolute position
        if (!container) {
            console.info('SSO: No container with id="sso-menu" found, creating absolute positioned menu');
            container = document.createElement('div');
            container.id = 'sso-menu-absolute';
            container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999;';
            document.body.appendChild(container);
            isAbsolute = true;
        }

        // Create styles
        const style = document.createElement('style');
        style.textContent = ` + "`" + `
            #sso-menu-absolute {
                position: fixed !important;
                top: 20px !important;
                right: 20px !important;
                z-index: 9999 !important;
            }

            .sso-account-button {
                position: relative;
                width: 40px;
                height: 40px;
                border-radius: 50%;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border: 2px solid #fff;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
                font-size: 16px;
                transition: transform 0.2s, box-shadow 0.2s;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
                user-select: none;
            }

            .sso-account-button:hover {
                transform: scale(1.05);
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
            }

            .sso-account-button:active {
                transform: scale(0.95);
            }

            .sso-dropdown {
                position: absolute;
                top: calc(100% + 10px);
                right: 0;
                background: white;
                border-radius: 8px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
                min-width: 200px;
                opacity: 0;
                visibility: hidden;
                transform: translateY(-10px);
                transition: opacity 0.2s, transform 0.2s, visibility 0.2s;
                z-index: 1000;
            }

            .sso-dropdown.active {
                opacity: 1;
                visibility: visible;
                transform: translateY(0);
            }

            .sso-dropdown::before {
                content: '';
                position: absolute;
                top: -6px;
                right: 16px;
                width: 12px;
                height: 12px;
                background: white;
                transform: rotate(45deg);
                box-shadow: -2px -2px 4px rgba(0, 0, 0, 0.05);
            }

            .sso-user-info {
                padding: 16px;
                border-bottom: 1px solid #e5e7eb;
            }

            .sso-user-name {
                font-weight: 600;
                color: #111827;
                margin-bottom: 4px;
                word-break: break-word;
            }

            .sso-user-email {
                font-size: 14px;
                color: #6b7280;
                word-break: break-word;
            }

            .sso-menu-items {
                padding: 8px 0;
            }

            .sso-menu-item {
                display: flex;
                align-items: center;
                padding: 10px 16px;
                color: #374151;
                text-decoration: none;
                transition: background 0.2s;
                cursor: pointer;
                border: none;
                background: none;
                width: 100%;
                text-align: left;
                font-size: 14px;
            }

            .sso-menu-item:hover {
                background: #f3f4f6;
            }

            .sso-menu-item-icon {
                margin-right: 12px;
                width: 20px;
                height: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .sso-menu-divider {
                height: 1px;
                background: #e5e7eb;
                margin: 8px 0;
            }

            .sso-overlay {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                z-index: 999;
                display: none;
            }

            .sso-overlay.active {
                display: block;
            }
        ` + "`" + `;
        document.head.appendChild(style);

        // Get user info from meta tags or data attributes
        const userData = getUserData();
        // Get app links from meta tags
        const appLinks = getAppLinks();

        // Create account button
        const accountButton = document.createElement('div');
        accountButton.className = 'sso-account-button';
        accountButton.setAttribute('aria-label', 'Account menu');
        accountButton.setAttribute('role', 'button');
        accountButton.innerHTML = userData.initials || 'U';

        // Build app links HTML
        let appLinksHTML = '';
        if (appLinks.length > 0) {
            appLinksHTML = '';
            for (const app of appLinks) {
                appLinksHTML += ` + "`" + `
                    <a href="${app.url}" class="sso-menu-item">
                        <span class="sso-menu-item-icon">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                        </span>
                        ${app.name}
                    </a>` + "`" + `;
            }
            appLinksHTML += '<div class="sso-menu-divider"></div>';
        }

        // Create dropdown menu
        const dropdown = document.createElement('div');
        dropdown.className = 'sso-dropdown';
        dropdown.innerHTML = ` + "`" + `
            <div class="sso-user-info">
                <div class="sso-user-name">${userData.name || 'User'}</div>
                <div class="sso-user-email">${userData.email || 'user@example.com'}</div>
            </div>
            <div class="sso-menu-items">
                ${appLinksHTML}
                <button class="sso-menu-item" onclick="window.ssoLogout()">
                    <span class="sso-menu-item-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                        </svg>
                    </span>
                    Logout
                </button>
            </div>
        ` + "`" + `;

        // Create overlay for closing dropdown
        const overlay = document.createElement('div');
        overlay.className = 'sso-overlay';

        // Add elements to container
        // Only set relative positioning if not using absolute positioning
        if (!isAbsolute) {
            container.style.position = 'relative';
        }
        container.appendChild(accountButton);
        container.appendChild(dropdown);
        container.appendChild(overlay);

        // Toggle dropdown on button click
        accountButton.addEventListener('click', function(e) {
            e.stopPropagation();
            const isActive = dropdown.classList.contains('active');
            if (isActive) {
                closeDropdown();
            } else {
                openDropdown();
            }
        });

        // Close dropdown on overlay click
        overlay.addEventListener('click', closeDropdown);

        // Close dropdown on escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && dropdown.classList.contains('active')) {
                closeDropdown();
            }
        });

        function openDropdown() {
            dropdown.classList.add('active');
            overlay.classList.add('active');
        }

        function closeDropdown() {
            dropdown.classList.remove('active');
            overlay.classList.remove('active');
        }

        // Global logout function
        window.ssoLogout = function() {
            // Get the current page URL to use as home-url
            const currentUrl = window.location.href;
            const welcomeUrl = '/oauth/welcome?home-url=' + encodeURIComponent(currentUrl);
            const encodedWelcomeUrl = encodeURIComponent(welcomeUrl);
            window.location.href = ` + "`/oauth/logout?redirect_uri=${encodedWelcomeUrl}`" + `;
        };

        // Helper function to get app links from meta tags
        function getAppLinks() {
            const apps = [];
            let i = 0;

            // Look for app meta tags with pattern sso-app-{index}-url and sso-app-{index}-name
            while (true) {
                const urlMeta = document.querySelector(` + "`meta[name=\"sso-app-${i}-url\"]`" + `);
                const nameMeta = document.querySelector(` + "`meta[name=\"sso-app-${i}-name\"]`" + `);

                if (!urlMeta || !nameMeta) {
                    break;
                }

                apps.push({
                    url: urlMeta.content,
                    name: nameMeta.content
                });

                i++;
            }

            return apps;
        }

        // Helper function to get user data
        function getUserData() {
            // Try to get data from meta tags
            let name = document.querySelector('meta[name="sso-user-name"]')?.content;
            let email = document.querySelector('meta[name="sso-user-email"]')?.content;

            // Try to get data from container attributes
            if (!name) name = container.getAttribute('data-user-name');
            if (!email) email = container.getAttribute('data-user-email');

            // Try to get from global object
            if (!name && window.ssoUser) name = window.ssoUser.name;
            if (!email && window.ssoUser) email = window.ssoUser.email;

            // Generate initials
            let initials = 'U';
            if (name) {
                const parts = name.trim().split(' ');
                if (parts.length >= 2) {
                    initials = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                } else if (parts.length === 1) {
                    initials = parts[0].substring(0, 2).toUpperCase();
                }
            }

            return { name, email, initials };
        }
    }
})();`
}
