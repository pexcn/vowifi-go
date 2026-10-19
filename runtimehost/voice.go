package runtimehost

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/iniwex5/vowifi-go/internal/ims"
	"github.com/iniwex5/vowifi-go/internal/netstack"
	"github.com/iniwex5/vowifi-go/runtimehost/voicehost"
)

type ownedVoice struct {
	gateway  *voicehost.Gateway
	deviceID string
	agent    *ims.VoiceAgent
}

func (v *ownedVoice) Close() error {
	v.gateway.UnregisterAgent(v.deviceID, v.agent)
	return v.agent.Close()
}

func registerVoice(ctx context.Context, req StartRequest, inst *Instance, svc *ims.Service, network *netstack.Network, _ netip.Addr) error {
	if req.VoiceGateway == nil {
		return nil
	}
	addr := svc.LocalAddress()
	if addr == nil {
		return errors.New("IMS transport closed before voice installation")
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return err
	}
	agent, err := ims.NewVoiceAgent(svc, ims.VoiceConfig{DeviceID: req.DeviceID, LocalAddress: host, ListenPacket: network.ListenPacket, NotifyIncoming: func(caller, callee string) { req.VoiceGateway.NotifyIncomingCall(req.DeviceID, caller, callee) }})
	if err != nil {
		return err
	}
	req.VoiceGateway.RegisterAgent(req.DeviceID, agent)
	return inst.own(&ownedVoice{gateway: req.VoiceGateway, deviceID: req.DeviceID, agent: agent})
}
