package handler

import (
	"encoding/xml"
	"github.com/joshblakeley/web-sso-saml/model"
	"net/http"
)

func (h *Handler) HandleMetadata(w http.ResponseWriter, r *http.Request) {

	buf, _ := xml.MarshalIndent(model.Middleware.ServiceProvider.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(buf)
	return
}
