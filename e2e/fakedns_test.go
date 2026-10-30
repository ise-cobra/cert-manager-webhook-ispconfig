//go:build e2e

package e2e

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig/ddnstest"
)

// recordTTL is deliberately small: the suite polls at short intervals, and a resolver
// should not cache anything.
const recordTTL = 5

// fakeDNS is an authoritative UDP name server for the test zone. It reads exclusively from
// the ddnstest.RecordStore written by the fake DDNS server — so the conformance suite sees, in
// its real DNS queries, exactly the records that the solver created via the DDNS API.
//
// The 60 s cron delay of a real ISPConfig installation is not reproduced: the fake
// propagates immediately. The solver is under test, not the patience of the suite.
type fakeDNS struct {
	t     *testing.T
	store *ddnstest.RecordStore
	// zone is the canonical name of the test zone, e.g. "example.com.".
	zone string
	addr string
}

// newFakeDNS binds a free UDP port on 127.0.0.1, starts the server and stops it via
// t.Cleanup. The function only returns once the server is running.
func newFakeDNS(t *testing.T, store *ddnstest.RecordStore, zone string) *fakeDNS {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err, "could not bind UDP port for the fake DNS server")

	f := &fakeDNS{
		t:     t,
		store: store,
		zone:  dns.CanonicalName(zone),
		addr:  conn.LocalAddr().String(),
	}

	// NotifyStartedFunc is the handshake miekg/dns provides for this. Without it, t.Cleanup
	// can run Shutdown before ActivateAndServe has marked the server as started: Shutdown
	// then reports "server not started", the server keeps running, and waiting on served
	// blocks until the panic timeout of the test run. That the port is already bound only
	// covers reachability, not this state.
	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn:        conn,
		Handler:           dns.HandlerFunc(f.handle),
		NotifyStartedFunc: func() { close(started) },
	}
	served := make(chan error, 1)
	go func() {
		served <- srv.ActivateAndServe()
	}()

	select {
	case <-started:
	case err := <-served:
		require.NoError(t, err, "fake DNS: server did not start")
		t.Fatal("fake DNS: server exited without error before it had started")
	}

	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("fake DNS: shutdown failed: %v", err)
		}
		if err := <-served; err != nil {
			t.Errorf("fake DNS: server exited with error: %v", err)
		}
	})

	return f
}

// server returns the address in the form 127.0.0.1:<port> for acmetest.SetDNSServer.
func (f *fakeDNS) server() string {
	return f.addr
}

func (f *fakeDNS) handle(w dns.ResponseWriter, req *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	if req.Opcode == dns.OpcodeQuery {
		for _, q := range msg.Question {
			f.answer(q, msg)
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		f.t.Errorf("fake DNS: could not write response: %v", err)
	}
}

// answer answers a single question.
//
// SERVFAIL is deliberately never returned: cert-manager's checkAuthoritativeNss treats anything
// other than NOERROR and NXDOMAIN as a hard error and aborts the wait logic. Unknown types
// therefore get NOERROR with an empty answer.
func (f *fakeDNS) answer(q dns.Question, msg *dns.Msg) {
	name := dns.CanonicalName(q.Name)

	if !dns.IsSubDomain(f.zone, name) {
		msg.Rcode = dns.RcodeNameError
		return
	}

	switch q.Qtype {
	case dns.TypeTXT:
		values := f.store.Lookup(name)
		if len(values) == 0 {
			// No value present: the suite reads NXDOMAIN as "record is gone" or as
			// "not yet propagated".
			msg.Rcode = dns.RcodeNameError
			return
		}
		for _, value := range values {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: recordTTL},
				Txt: []string{value},
			})
		}
	case dns.TypeSOA:
		msg.Answer = append(msg.Answer, f.soa())
	case dns.TypeNS:
		msg.Answer = append(msg.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: f.zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: recordTTL},
			Ns:  f.nameserver(),
		})
	default:
		// CNAME, CAA and everything else: NOERROR without answer. cert-manager follows the CNAME
		// chain before the TXT check; an empty answer ends it at the original name.
	}
}

func (f *fakeDNS) soa() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: f.zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: recordTTL},
		Ns:      f.nameserver(),
		Mbox:    "hostmaster." + f.zone,
		Serial:  1,
		Refresh: recordTTL,
		Retry:   recordTTL,
		Expire:  recordTTL,
		Minttl:  recordTTL,
	}
}

func (f *fakeDNS) nameserver() string {
	return "ns1." + f.zone
}
