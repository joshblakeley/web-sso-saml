package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"strconv"

	"github.com/crewjam/saml"

	"github.com/crewjam/saml/samlsp"
)


var (
	logger = logrus.New()
)


var Middleware *samlsp.Middleware



type SAMLConfig struct {
	IDPMetadataURL      string
	CertFile            string
	KeyFile             string
	ForceAuthentication bool
	SAMLBinding         string
	BaseURL string
}


func initialise() {
	config := &SAMLConfig{
		IDPMetadataURL: "https://login.microsoftonline.com/2a3490ef-c3df-4323-ae94-a75f83817991/federationmetadata/2007-06/federationmetadata.xml?appid=336fcc57-ddf4-4748-ab81-69dadbaf2648",                  //os.Getenv("TYK_SAML_METADATA_URL"),
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

		metadataURL := rootURL.ResolveReference(&url.URL{Path: "websso/saml/metadata"})
		acsURL := rootURL.ResolveReference(&url.URL{Path: "websso/saml/acs"})
		sloURL := rootURL.ResolveReference(&url.URL{Path: "websso/saml/slo"})

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

		Middleware = &samlsp.Middleware{
			ServiceProvider: sp,
			Binding:         config.SAMLBinding,
			OnError:         samlsp.DefaultOnError,
			Session:         samlsp.DefaultSessionProvider(opts),
		}
		Middleware.RequestTracker = samlsp.DefaultRequestTracker(opts, &Middleware.ServiceProvider)

		logger.Info("SAML Middleware initialised")
}




type Handler struct {
	Config *SAMLConfig
}

func (h *Handler) writeJSON(w http.ResponseWriter, data interface{}, code int) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(dataBytes)))
	_, err = w.Write(dataBytes)
	return err
}

func HandleAuth() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		session, err := Middleware.Session.GetSession(r)
		if session != nil {
			r = r.WithContext(samlsp.ContextWithSession(r.Context(), session))
			//ServeHTTP(w, r)
			return
		}
		if err == samlsp.ErrNoSession {
			Middleware.HandleStartAuthFlow(w, r)
			return
		}
	}
}


func HandleACS(w http.ResponseWriter, r *http.Request) {


	err := r.ParseForm()
	if err != nil {
		logger.Errorf("Error parsing form: %v", err)
	}

	var possibleRequestIDs = make([]string, 0)
	if Middleware.ServiceProvider.AllowIDPInitiated {
		logger.Debug("allowing IDP initiated ID")
		possibleRequestIDs = append(possibleRequestIDs, "")
	}

	trackedRequests := Middleware.RequestTracker.GetTrackedRequests(r)
	for _, tr := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
	}
	assertion, err := Middleware.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	resp, _ := xml.Marshal(assertion.AttributeStatements)

	// TODO: we are successful so carry on proxying as usual

	w.Write(resp)
	return
}

func HandleMetadata(object *coprocess.Object) *coprocess.Object{
	buf, _ := xml.MarshalIndent(Middleware.ServiceProvider.Metadata(), "", "  ")
	object.Request.ReturnOverrides.Headers = map[string]string{"Content-Type": "application/samlmetadata+xml"}
	object.Request.ReturnOverrides.ResponseBody = string(buf)
	object.Request.ReturnOverrides.ResponseCode = 200

	return object
}


// AuthPlugin catches all requests made to this api, and uses it's own internal router
// to handle auth requests & issue access tokens
func SAMLWebSSO(object *coprocess.Object) (*coprocess.Object, error){

	logger.Info("HELLO")

	if object.Request.RequestUri == "websso/saml/metadata"{
		return HandleMetadata(object), nil
	}

	if object.Request.RequestUri == "websso/saml/acs"{

	}




	return object, nil
}
