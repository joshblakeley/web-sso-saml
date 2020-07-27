package model

import (
	"github.com/TykTechnologies/tyk/log"
	"github.com/crewjam/saml/samlsp"
)

var Logger =log.Get()
var Middleware *samlsp.Middleware



type SAMLConfig struct {
	IDPMetadataURL      string
	CertFile            string
	KeyFile             string
	ForceAuthentication bool
	SAMLBinding         string
	BaseURL string
}
