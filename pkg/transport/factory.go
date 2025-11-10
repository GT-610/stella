package transport

import (
	"errors"
)

type TransportType string

const (
	TransportTypeUDP TransportType = "udp"
	TransportTypeTCP TransportType = "tcp"
)

func NewTransport(transportType TransportType, config map[string]interface{}) (Transport, error) {
	switch transportType {
	case TransportTypeUDP:
		transport := NewUDPTransport()
		if err := transport.Init(config); err != nil {
			return nil, err
		}
		return transport, nil
	case TransportTypeTCP:
		return nil, errors.New("TCP transport not implemented yet")
	default:
		return nil, errors.New("unsupported transport type")
	}
}

func NewConnectionManager(transport Transport) ConnectionManager {
	return NewDefaultConnectionManager(transport)
}
