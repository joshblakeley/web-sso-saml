package handler

import (
	"encoding/xml"
	"github.com/joshblakeley/web-sso-saml/model"
	"net/http"
)

func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {


	err := r.ParseForm()
	if err != nil {
		model.Logger.Errorf("Error parsing form: %v", err)
	}

	var possibleRequestIDs = make([]string, 0)
	if model.Middleware.ServiceProvider.AllowIDPInitiated {
		model.Logger.Debug("allowing IDP initiated ID")
		possibleRequestIDs = append(possibleRequestIDs, "")
	}

	trackedRequests := model.Middleware.RequestTracker.GetTrackedRequests(r)
	for _, tr := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
	}
	assertion, err := model.Middleware.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	resp, _ := xml.Marshal(assertion.AttributeStatements)

	// TODO: we are successful so carry on proxying as usual

	w.Write(resp)
	return


}
