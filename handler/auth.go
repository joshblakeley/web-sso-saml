package handler

import (
	"github.com/crewjam/saml"
	"github.com/joshblakeley/web-sso-saml/model"
	"net/http"
)

func (h *Handler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	// If we try to redirect when the original request is the ACS URL we'll
	// end up in a loop so just fail and error instead
	if r.URL.Path == model.Middleware.ServiceProvider.AcsURL.Path {
		return
	}

	var binding, bindingLocation string
	if model.Middleware.Binding != "" {
		binding = model.Middleware.Binding
		bindingLocation = model.Middleware.ServiceProvider.GetSSOBindingLocation(binding)
	} else {
		binding = saml.HTTPRedirectBinding
		bindingLocation = model.Middleware.ServiceProvider.GetSSOBindingLocation(binding)
		if bindingLocation == "" {
			binding = saml.HTTPPostBinding
			bindingLocation = model.Middleware.ServiceProvider.GetSSOBindingLocation(binding)
		}
	}
	model.Logger.Debugf("Binding: %v", binding)
	model.Logger.Debugf("BindingLocation: %v", bindingLocation)

	authReq, err := model.Middleware.ServiceProvider.MakeAuthenticationRequest(bindingLocation)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// relayState is limited to 80 bytes but also must be integrity protected.
	// this means that we cannot use a JWT because it is way to long. Instead
	// we set a signed cookie that encodes the original URL which we'll check
	// against the SAML response when we get it.
	relayState, err := model.Middleware.RequestTracker.TrackRequest(w, r, authReq.ID)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if binding == saml.HTTPRedirectBinding {
		redirectURL := authReq.Redirect(relayState)
		w.Header().Add("Location", redirectURL.String())
		w.WriteHeader(http.StatusFound)
		return
	}
	if binding == saml.HTTPPostBinding {
		w.Header().Add("Content-Security-Policy", ""+
			"default-src; "+
			"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
			"reflected-xss block; referrer no-referrer;")
		w.Header().Add("Content-type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><body>`))
		w.Write(authReq.Post(relayState))
		w.Write([]byte(`</body></html>`))
		return
	}
}
