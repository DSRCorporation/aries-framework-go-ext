package cheqd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

var logger = log.New("aries-framework-go-ext/vdr/cheqd")

// VDR implements the VDR interface.
type VDR struct {
	endpointURL      string
	client           *http.Client
	accept           Accept
	resolveAuthToken string
}

// Accept is method to accept did method.
type Accept func(method string) bool

// Option configures the peer vdr.
type Option func(opts *VDR)

// New creates new DID Resolver.
func New(endpointURL string, opts ...Option) (*VDR, error) {
	v := &VDR{client: &http.Client{}, accept: func(method string) bool { return method == "cheqd" }}

	// Validate host
	_, err := url.ParseRequestURI(endpointURL)
	if err != nil {
		return nil, fmt.Errorf("base URL invalid: %w", err)
	}

	v.endpointURL = endpointURL

	return v, nil
}

// WithAccept option is for accept did method.
func WithAccept(accept Accept) Option {
	return func(opts *VDR) {
		opts.accept = accept
	}
}

// Accept did method - attempt to resolve any method.
func (v *VDR) Accept(method string) bool {
	return v.accept(method)
}

// Update did doc.
func (v *VDR) Update(didDoc *diddoc.Doc, opts ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Deactivate did doc.
func (v *VDR) Deactivate(did string, opts ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Close method of the VDR interface.
func (v *VDR) Close() error {
	return nil
}

// Read resolves a did:cheqd did.
func (v *VDR) Read(didID string) (*did.DocResolution, error) {
	httpClient := &http.Client{}

	address := parseDIDCheqd(v.endpointURL, didID)

	req, err := http.NewRequest("GET", address, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("error GET request from %s", address)
	}

	req.Header.Add("Accept", "application/ld+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:cheqd did --> http request unsuccessful --> %w", err)
	}

	defer closeResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http server returned status code [%d]", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:cheqd did --> error reading https response body: %s --> %w", body, err)
	}

	rawDocCheqd := &RawDocCheqd{}
	if err = json.Unmarshal(body, &rawDocCheqd); err != nil {
		return nil, fmt.Errorf("error unmarshal did:cheqd did --> error unmarshal https response body: %s --> %w", body, err)
	}

	rawDoc := convertTypeRawDocCheqdToRawDoc(rawDocCheqd)

	body, err = json.Marshal(rawDoc)
	if err != nil {
		return nil, fmt.Errorf("error marshal did:cheqd did --> error marshaling https response body: %s --> %w", body, err)
	}

	doc, err := did.ParseDocument(body)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:cheqd did --> error parsing did doc --> %w", err)
	}

	return &did.DocResolution{DIDDocument: doc}, nil
}

// RawDocCheqd type.
type RawDocCheqd struct {
	DidDocument           did.Doc               `json:"didDocument"`
	DidDocumentMetadata   DidDocumentMetadata   `json:"didDocumentMetadata"`
	DidResolutionMetadata DidResolutionMetadata `json:"didResolutionMetadata"`
}

// DidDocument type.
type DidDocument struct {
	Context            []string             `json:"@context"`
	Authentication     []string             `json:"authentication"`
	ID                 string               `json:"id"`
	Service            []Service            `json:"service"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
}

// Service type.
type Service struct {
	ID              string `json:"id"`
	ServiceEndpoint string `json:"serviceEndpoint"`
	Type            string `json:"type"`
}

// VerificationMethod type.
type VerificationMethod struct {
	Controller         string `json:"controller"`
	ID                 string `json:"id"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	Type               string `json:"type"`
}

// DidDocumentMetadata type.
type DidDocumentMetadata struct {
	Created   string `json:"created"`
	VersionID string `json:"versionId"`
}

// DidResolutionMetadata type.
type DidResolutionMetadata struct {
	ContentType string `json:"contentType"`
	Retrieved   string `json:"retrieved"`
	DID         DID    `json:"did"`
}

// DID type.
type DID struct {
	DIDString        string `json:"didString"`
	MethodSpecificID string `json:"methodSpecificId"`
	Method           string `json:"method"`
}

func convertTypeRawDocCheqdToRawDoc(rawDocCheqd *RawDocCheqd) *did.Doc {
	rawDoc := &did.Doc{
		Context:            rawDocCheqd.DidDocument.Context,
		ID:                 rawDocCheqd.DidDocument.ID,
		VerificationMethod: rawDocCheqd.DidDocument.VerificationMethod,
		Service:            rawDocCheqd.DidDocument.Service,
		Authentication:     rawDocCheqd.DidDocument.Authentication,
	}

	return rawDoc
}

func parseDIDCheqd(endpointURL string, id string) string {
	return endpointURL + id
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		logger.Errorf("Failed to close response body: %v", e)
	}
}
