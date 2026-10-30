// Package solver implements the webhook.Solver interface of cert-manager: it
// reads the issuer configuration, resolves the DDNS token from a Kubernetes
// secret and creates or removes the challenge TXT record via the ISPConfig
// DDNS client.
package solver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig"
)

const (
	// SolverName is the fixed name of this solver. It must match solverName in the
	// DNS01 configuration of the ACME issuer.
	SolverName = "ispconfig"

	// challengeTypeDNS01 is the only supported challenge type.
	challengeTypeDNS01 = "dns-01"
)

// Sentinel errors that callers and tests can check with errors.Is.
var (
	// ErrConfig reports an unusable configuration — in the config block of the issuer
	// or in the referenced secret.
	ErrConfig = errors.New("invalid solver configuration")
	// ErrInvalidChallenge reports a ChallengeRequest the solver cannot
	// process.
	ErrInvalidChallenge = errors.New("invalid ChallengeRequest")
	// ErrNotInitialized reports a call before successful initialization.
	ErrNotInitialized = errors.New("solver is not initialized")
)

// Solver satisfies the webhook.Solver interface of cert-manager.
var _ webhook.Solver = (*Solver)(nil)

// ddnsClient is the subset of the DDNS client this package needs.
type ddnsClient interface {
	AddTXTRecord(ctx context.Context, record, value string) (ispconfig.Outcome, error)
	DeleteTXTRecord(ctx context.Context, record, value string) (ispconfig.Outcome, error)
}

// challengeAction distinguishes the two directions of the shared flow of Present and
// CleanUp. Deliberately not whapi.ChallengeAction ("Present"/"CleanUp"): all other log and
// metric values of this service are lowercase (add/delete, changed/unchanged).
type challengeAction string

const (
	actionPresent challengeAction = "present"
	actionCleanUp challengeAction = "cleanup"
)

// Solver serves the DNS01 challenges of cert-manager against the
// ISPConfig DDNS API.
type Solver struct {
	// defaults are the default values configured at service startup.
	defaults Defaults

	// newClient creates the DDNS client. Stored as a field so that tests can
	// replace it.
	newClient func(ispconfig.Config) (ddnsClient, error)

	// logger receives the log lines of the challenges.
	logger *slog.Logger

	// mu guards clientset: Initialize may run concurrently with Present/CleanUp.
	mu        sync.RWMutex
	clientset kubernetes.Interface
}

// New creates the solver with the defaults configured at startup. logger receives the log
// lines of the challenges; nil means slog.Default(). An explicit parameter so that the lines
// do not depend on someone having called slog.SetDefault beforehand.
func New(defaults Defaults, logger *slog.Logger) *Solver {
	if logger == nil {
		logger = slog.Default()
	}

	return &Solver{
		defaults:  defaults,
		newClient: newDDNSClient,
		logger:    logger,
	}
}

// newDDNSClient builds the real DDNS client.
func newDDNSClient(cfg ispconfig.Config) (ddnsClient, error) {
	client, err := ispconfig.New(cfg)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Name returns the name of the solver within the API group.
func (s *Solver) Name() string {
	return SolverName
}

// Initialize sets up the Kubernetes API access needed to resolve the tokenSecretRef.
// Idempotent: the cert-manager conformance suite starts the solver several times per test
// run. stopCh stays unused, the solver holds nothing that would have to be stopped on
// shutdown.
func (s *Solver) Initialize(kubeClientConfig *restclient.Config, _ <-chan struct{}) error {
	if kubeClientConfig == nil {
		return fmt.Errorf("%w: no Kubernetes client configuration passed, the token cannot be resolved without API access",
			ErrConfig)
	}

	clientset, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("create Kubernetes clientset: %w", err)
	}

	s.mu.Lock()
	s.clientset = clientset
	s.mu.Unlock()

	s.log().Debug("solver initialized", slog.String("solver", SolverName))

	return nil
}

// Present creates the TXT record of the challenge.
func (s *Solver) Present(ch *whapi.ChallengeRequest) error {
	return s.handle(ch, actionPresent)
}

// CleanUp removes exactly the TXT record of this challenge.
func (s *Solver) CleanUp(ch *whapi.ChallengeRequest) error {
	return s.handle(ch, actionCleanUp)
}

// handle is the shared flow of Present and CleanUp.
func (s *Solver) handle(ch *whapi.ChallengeRequest, action challengeAction) error {
	if ch == nil {
		return fmt.Errorf("%w: no ChallengeRequest passed", ErrInvalidChallenge)
	}

	// cert-manager delivers ResolvedFQDN with a trailing dot, the DDNS API
	// expects the record name without it.
	record := recordName(ch.ResolvedFQDN)

	logger := s.log().With(
		slog.String("action", string(action)),
		slog.String("record", record),
		slog.String("dnsName", ch.DNSName),
		slog.String("uid", string(ch.UID)),
		slog.String("namespace", ch.ResourceNamespace),
	)
	// The challenge key is not a secret, but noise — hence debug only.
	logger.Debug("challenge accepted", slog.String("challengeKey", ch.Key))

	if err := validateChallenge(ch, record); err != nil {
		logger.Error("ChallengeRequest rejected", slog.Any("err", err))

		return err
	}

	cfg, err := parseConfig(ch.Config, s.defaults)
	if err != nil {
		logger.Error("solver configuration rejected", slog.Any("err", err))

		return err
	}

	clientset, err := s.kubeClient()
	if err != nil {
		logger.Error("no Kubernetes access", slog.Any("err", err))

		return err
	}

	// cert-manager passes no context, so the chain starts here — the budget is httpTimeout
	// plus the reserve for resolving the secret, otherwise a slow API server would eat up
	// the time of the DDNS call.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.httpTimeout+secretResolveTimeout)
	defer cancel()

	tok, err := resolveToken(ctx, clientset, ch.ResourceNamespace, cfg.tokenSecretRef)
	if err != nil {
		logger.Error("cannot resolve DDNS token",
			slog.String("secret", cfg.tokenSecretRef.Name), slog.Any("err", err))

		return fmt.Errorf("resolve DDNS token for record %s: %w", record, err)
	}

	client, err := s.newClient(ispconfig.Config{
		Endpoint:              cfg.endpoint,
		Token:                 tok.value,
		AuthMode:              cfg.tokenAuthMode,
		Timeout:               cfg.httpTimeout,
		AllowInsecureEndpoint: s.defaults.AllowInsecureEndpoint,
		// The client inherits the logger including the correlation fields of this
		// challenge, so that its lines can be attributed to the same operation.
		Logger: logger,
	})
	if err != nil {
		logger.Error("cannot create DDNS client", slog.Any("err", err))

		return fmt.Errorf("create DDNS client: %w", err)
	}

	outcome, err := invoke(ctx, client, action, record, ch.Key)
	if err != nil {
		// Deleting a record that no longer exists: the desired state is reached.
		// An error would leave the challenge stuck permanently.
		if action == actionCleanUp && errors.Is(err, ispconfig.ErrRecordNotFound) {
			logger.Info("TXT record no longer exists, cleanup considered done")

			return nil
		}

		// Except for rejected input (record/value), the failure is already logged in
		// internal/ispconfig — only wrap and return it here.
		return fmt.Errorf("DDNS action %s for record %s failed: %w", action, record, err)
	}

	if outcome == ispconfig.OutcomeUnchanged {
		logger.Info("TXT record already in the desired state, no change needed")

		return nil
	}

	logger.Info("TXT record changed")

	return nil
}

// invoke calls the DDNS client method that matches the action.
func invoke(
	ctx context.Context,
	client ddnsClient,
	action challengeAction,
	record, value string,
) (ispconfig.Outcome, error) {
	if action == actionCleanUp {
		return client.DeleteTXTRecord(ctx, record, value)
	}

	return client.AddTXTRecord(ctx, record, value)
}

// validateChallenge checks the fields without which no DDNS call is possible. record is the
// record name derived from ResolvedFQDN; it is checked as well, so that an FQDN consisting
// only of dots surfaces here as ErrInvalidChallenge and not later in the client as
// ErrInvalidRecord.
func validateChallenge(ch *whapi.ChallengeRequest, record string) error {
	if ch.ResolvedFQDN == "" {
		return fmt.Errorf("%w: ResolvedFQDN is missing, no TXT record is possible without a record name",
			ErrInvalidChallenge)
	}

	if record == "" {
		return fmt.Errorf("%w: ResolvedFQDN %q yields no record name",
			ErrInvalidChallenge, ch.ResolvedFQDN)
	}

	// An empty Type field is allowed: the cert-manager conformance suite does not set
	// Type and Action, and the dispatch to Present/CleanUp is already done by the
	// calling layer. Only a set, different type is an error.
	if ch.Type != "" && ch.Type != challengeTypeDNS01 {
		return fmt.Errorf("%w: challenge type %q is not supported, expected %q",
			ErrInvalidChallenge, ch.Type, challengeTypeDNS01)
	}

	if ch.Key == "" {
		return fmt.Errorf("%w: Key is missing, there is no TXT value without a challenge key", ErrInvalidChallenge)
	}

	return nil
}

// kubeClient returns the clientset set in Initialize.
func (s *Solver) kubeClient() (kubernetes.Interface, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.clientset == nil {
		return nil, fmt.Errorf("%w: Initialize did not complete successfully", ErrNotInitialized)
	}

	return s.clientset, nil
}

// log returns the logger to use. The fallback only applies when a test builds the solver
// as a literal instead of via New.
func (s *Solver) log() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}

	return slog.Default()
}

// recordName turns the FQDN from cert-manager into the record name of the DDNS API. TrimRight
// instead of TrimSuffix: TrimSuffix would remove only one dot and leave one on a double dot.
func recordName(fqdn string) string {
	return strings.TrimRight(strings.TrimSpace(fqdn), ".")
}
