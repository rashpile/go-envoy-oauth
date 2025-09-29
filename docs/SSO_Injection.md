# SSO Script Injection Feature

## Overview

The SSO Script Injection feature automatically injects a Single Sign-On (SSO) user menu into HTML pages served through the OAuth-authenticated gateway. This provides users with a consistent authentication experience across all protected applications, showing user information and providing quick access to logout and other configured applications.

## How It Works

1. **HTML Detection**: The filter detects HTML responses by checking the Content-Type header for `text/html`
2. **Script Injection**: For authenticated users, the filter injects a JavaScript file reference into the HTML
3. **Data Fetching**: The injected JavaScript fetches user data from the `/oauth/user` API endpoint
4. **Menu Rendering**: The JavaScript creates an account button in the top-right corner showing:
   - User initials in a circular button
   - Dropdown menu with user info, application links, and logout option

## Configuration

### Per-Cluster Configuration

Enable SSO injection for specific clusters in your gateway configuration:

```yaml
clients:
  - id: my_app_cluster
    address: app.example.com
    port: 8080
    sso_injection: true          # Enable SSO script injection for this cluster
    sso_appurl: http://app.example.com    # URL for this app in the menu
    sso_appname: My Application           # Display name in the menu
```

### Configuration Fields

- `sso_injection` (bool): Enable/disable SSO script injection for HTML responses from this cluster
- `sso_appurl` (string): URL to link to this application in the SSO menu
- `sso_appname` (string): Display name for this application in the SSO menu

## User Interface

### Account Button
- Circular button positioned in the top-right corner (fixed position)
- Displays user initials extracted from the user's name
- Click to open dropdown menu

### Dropdown Menu Contents
1. **User Information Section**
   - User's full name
   - User's email address

2. **Application Links** (if configured)
   - Links to all clusters with `sso_appurl` and `sso_appname` configured
   - Displayed between user info and logout

3. **Logout Button**
   - Performs OIDC logout flow
   - Returns user to welcome page with option to return to original page

## Technical Implementation

### Response Modification Pipeline

1. **EncodeHeaders**: Checks Content-Type header for HTML responses
2. **EncodeData**: Modifies response body to inject script after `<head>` tag
3. **Script Injection**: Adds script reference to `/oauth/assets/sso.js`

### Injected Element

```html
<script src="/oauth/assets/sso.js" defer></script>
```

### JavaScript Behavior

The SSO script (`/oauth/assets/sso.js`) provides:

1. **API Data Fetching**: Makes a request to `/oauth/user` to get user info and configured applications
2. **Auto-positioning**: If no element with `id="sso-menu"` exists, creates a fixed-position container
3. **Menu Creation**: Builds and renders the dropdown menu with fetched data
4. **Logout Flow**: Handles logout with proper OIDC flow and post-logout redirect
5. **Error Handling**: Falls back to default values if API call fails

## Example Configuration

### Complete Example with Multiple Applications

```yaml
# gateway-auth.yaml
listener:
  address: 0.0.0.0
  port: 8080

oauth:
  issuer_url: https://auth.example.com
  client_id: gateway-client
  client_secret: secret
  redirect_url: /oauth/callback

clients:
  # Keycloak admin interface - with SSO injection
  - id: keycloak_cluster
    address: keycloak.internal
    domain: auth.example.com
    port: 8080
    ssl: false
    exclude: true  # Don't require auth for Keycloak itself
    prefix: /auth
    sso_injection: true
    sso_appurl: https://auth.example.com/auth
    sso_appname: Keycloak Admin

  # Main application - with SSO injection
  - id: main_app
    address: app.internal
    domain: app.example.com
    port: 3000
    ssl: false
    prefix: /
    sso_injection: true
    sso_appurl: https://app.example.com
    sso_appname: Main Application

  # API service - no SSO injection (not HTML)
  - id: api_service
    address: api.internal
    domain: api.example.com
    port: 8080
    prefix: /api
    sso_injection: false  # APIs don't need SSO UI

  # Monitoring dashboard - with SSO injection
  - id: monitoring
    address: grafana.internal
    domain: monitor.example.com
    port: 3000
    prefix: /
    sso_injection: true
    sso_appurl: https://monitor.example.com
    sso_appname: Monitoring
```

## Customization

### Using a Custom Container

If your HTML already has a designated container for the SSO menu, add a div with `id="sso-menu"`:

```html
<div id="sso-menu"></div>
```

The script will use this container instead of creating a fixed-position element.

### Styling

The SSO menu uses inline styles for consistency across applications. Key CSS classes:
- `.sso-account-button`: The circular user button
- `.sso-dropdown`: The dropdown menu container
- `.sso-menu-item`: Individual menu items
- `.sso-user-info`: User information section

## Security Considerations

1. **HTML Escaping**: All user data and configuration values are HTML-escaped before injection
2. **Content-Type Check**: Only injects into actual HTML responses
3. **Authentication Required**: Script only injected for authenticated sessions
4. **Secure Cookies**: Session cookies use secure flags when configured

## Troubleshooting

### Menu Not Appearing

1. Check that `sso_injection: true` is set for the cluster
2. Verify the response Content-Type includes `text/html`
3. Check browser console for JavaScript errors
4. Ensure user is authenticated (has valid session)
5. Verify `/oauth/user` endpoint is accessible and returns valid JSON

### Wrong User Information

1. Test the `/oauth/user` endpoint directly in browser
2. Verify OIDC provider returns correct claims
3. Check that `name` or `preferred_username` claim is present
4. Verify `email` claim is available in the session

### Application Links Missing

1. Ensure both `sso_appurl` and `sso_appname` are configured for each cluster
2. Test `/oauth/user` endpoint to verify apps array is populated
3. Check browser console for any JavaScript errors when rendering menu

## API Endpoints

### `/oauth/assets/sso.js`
- **Purpose**: Serves the SSO menu JavaScript
- **Method**: GET
- **Authentication**: Not required (public asset)
- **Cache**: 1 hour (`cache-control: public, max-age=3600`)

### `/oauth/user`
- **Purpose**: Returns current user information and configured applications as JSON
- **Method**: GET
- **Authentication**: Required (must have valid session)
- **Response Format**:
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "apps": [
    {
      "app": "Application Name",
      "url": "https://app.example.com"
    }
  ]
}
```
- **Status Codes**:
  - `200`: Success - returns user info
  - `401`: Unauthorized - no valid session
  - `500`: Internal error - failed to generate response

## Browser Compatibility

The SSO script uses modern JavaScript features and requires:
- ES6 support (template literals, arrow functions)
- querySelector API
- CSS3 for styling

Tested and supported on:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+