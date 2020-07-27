package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/gorilla/mux"
	"github.com/joshblakeley/web-sso-saml/handler"
	"github.com/joshblakeley/web-sso-saml/model"
	"net/http"
	"net/url"


	"github.com/crewjam/saml"

	"github.com/crewjam/saml/samlsp"


	)


var (
	httpHandler http.Handler
	logger = model.Logger
)




func init() {
	config := &model.SAMLConfig{
		IDPMetadataURL: "",                  //os.Getenv("TYK_SAML_METADATA_URL"),
		CertFile: "myservice.cert",
		KeyFile: "myservice.key",
		BaseURL: "http://localhost:8080",    //os.Getenv("TYK_SAML_BASE_URL"),
	}


		logger.Debug("Initialising middleware SAML")
		//needs to match the signing cert if IDP
		keyPair, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			logger.Errorf("Error loading keypair: %v", err)
		}

		keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			logger.Errorf("Error parsing certificate: %v", err)
		}

		idpMetadataURL, err := url.Parse(config.IDPMetadataURL)
		if err != nil {
			logger.Errorf("Error parsing IDP metadata URL: %v", err)
		}
		logger.Debugf("IDPmetadataURL is: %v", idpMetadataURL.String())

		rootURL, err := url.Parse(config.BaseURL)
		if err != nil {
			logger.Errorf("Error parsing SAMLBaseURL: %v", err)
		}

		httpClient := http.DefaultClient

		metadata, err := samlsp.FetchMetadata(context.TODO(), httpClient, *idpMetadataURL)
		if err != nil {
			logger.Errorf("Error retrieving IDP Metadata: %v", err)
		}

		logger.Debugf("Root URL: %v", rootURL.String())

		opts := samlsp.Options{
			URL: *rootURL,
			Key: keyPair.PrivateKey.(*rsa.PrivateKey),
		}

		metadataURL := rootURL.ResolveReference(&url.URL{Path: "/saml/metadata"})
		acsURL := rootURL.ResolveReference(&url.URL{Path: "/saml/callback"})
		sloURL := rootURL.ResolveReference(&url.URL{Path: "/saml/slo"})

		logger.Debugf("SP metadata URL: %v", metadataURL.String())
		logger.Debugf("SP acs URL: %v", acsURL.String())

		var forceAuthn = config.ForceAuthentication

		sp := saml.ServiceProvider{
			EntityID:          metadataURL.String(),
			Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate:       keyPair.Leaf,
			MetadataURL:       *metadataURL,
			AcsURL:            *acsURL,
			SloURL:            *sloURL,
			IDPMetadata:       metadata,
			ForceAuthn:        &forceAuthn,
			AllowIDPInitiated: true,
		}

		model.Middleware = &samlsp.Middleware{
			ServiceProvider: sp,
			Binding:         config.SAMLBinding,
			OnError:         samlsp.DefaultOnError,
			Session:         samlsp.DefaultSessionProvider(opts),
		}
		model.Middleware.RequestTracker = samlsp.DefaultRequestTracker(opts, &model.Middleware.ServiceProvider)

	httpHandler = configureRoutes(config)

}

func configureRoutes(config *model.SAMLConfig) http.Handler {
	r := mux.NewRouter()

	h := handler.Handler{Config: config}

	r.HandleFunc("/auth/saml/metadata", h.HandleMetadata)

	r.HandleFunc("/auth", h.HandleAuth)

	r.HandleFunc("/auth/saml/callback", h.HandleCallback)


	return r
}

// AuthPlugin catches all requests made to this api, and uses it's own internal router
// to handle auth requests & issue access tokens
func AuthPlugin(w http.ResponseWriter, r *http.Request) {
	httpHandler.ServeHTTP(w, r)
}