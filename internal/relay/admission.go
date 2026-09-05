package relay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/config"
)

const connectionAttemptWindow = time.Minute

var (
	errInvalidSourceAddress = errors.New("connection source address is invalid")
	errConnectionRate       = errors.New("connection source rate is exhausted")
	errConnectionCapacity   = errors.New("relay connection capacity is exhausted")
)

type sourceAdmission struct {
	windowStartedAt time.Time
	attempts        int
	active          int
}

type connectionAdmission struct {
	controller *admissionController
	source     netip.Addr
	once       sync.Once
}

func (admission *connectionAdmission) release() {
	if admission == nil || admission.controller == nil {
		return
	}
	admission.once.Do(func() {
		admission.controller.releaseConnection(admission.source)
	})
}

type admissionController struct {
	config config.Config
	clock  func() time.Time

	mu                sync.Mutex
	sources           map[netip.Addr]*sourceAdmission
	activeConnections int
	queuedBytes       int
}

func newAdmissionController(configuration config.Config) *admissionController {
	return &admissionController{
		config:  configuration,
		clock:   time.Now,
		sources: make(map[netip.Addr]*sourceAdmission),
	}
}

func canonicalRemoteIP(remoteAddress string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return netip.Addr{}, errInvalidSourceAddress
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, errInvalidSourceAddress
	}
	return address.Unmap(), nil
}

func (controller *admissionController) acquireConnection(
	remoteAddress string,
) (*connectionAdmission, error) {
	source, err := canonicalRemoteIP(remoteAddress)
	if err != nil {
		return nil, err
	}
	now := controller.clock()

	controller.mu.Lock()
	defer controller.mu.Unlock()
	current := controller.sources[source]
	if current == nil {
		if len(controller.sources) >= controller.config.MaxTrackedIPs {
			controller.pruneSourcesLocked(now)
		}
		if len(controller.sources) >= controller.config.MaxTrackedIPs {
			return nil, errConnectionCapacity
		}
		current = &sourceAdmission{windowStartedAt: now}
		controller.sources[source] = current
	}
	if now.Before(current.windowStartedAt) ||
		!now.Before(current.windowStartedAt.Add(connectionAttemptWindow)) {
		current.windowStartedAt = now
		current.attempts = 0
	}
	if current.attempts >= controller.config.ConnectionAttemptsPerMinute {
		return nil, errConnectionRate
	}
	current.attempts++
	if current.active >= controller.config.MaxConnectionsPerIP ||
		controller.activeConnections >= controller.config.MaxConnections {
		return nil, errConnectionCapacity
	}
	current.active++
	controller.activeConnections++
	return &connectionAdmission{controller: controller, source: source}, nil
}

func (controller *admissionController) pruneSourcesLocked(now time.Time) {
	for source, current := range controller.sources {
		if current.active == 0 &&
			!now.Before(current.windowStartedAt.Add(connectionAttemptWindow)) {
			delete(controller.sources, source)
		}
	}
}

func (controller *admissionController) releaseConnection(source netip.Addr) {
	now := controller.clock()
	controller.mu.Lock()
	defer controller.mu.Unlock()
	current := controller.sources[source]
	if current == nil || current.active <= 0 || controller.activeConnections <= 0 {
		return
	}
	current.active--
	controller.activeConnections--
	if current.active == 0 &&
		!now.Before(current.windowStartedAt.Add(connectionAttemptWindow)) {
		delete(controller.sources, source)
	}
}

func (controller *admissionController) reserveQueuedBytes(size int) bool {
	if size < 0 {
		return false
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if size > controller.config.MaxAggregateQueuedBytes-controller.queuedBytes {
		return false
	}
	controller.queuedBytes += size
	return true
}

func (controller *admissionController) releaseQueuedBytes(size int) bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if size < 0 || size > controller.queuedBytes {
		return false
	}
	controller.queuedBytes -= size
	return true
}
