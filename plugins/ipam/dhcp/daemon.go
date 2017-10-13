// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/coreos/go-systemd/activation"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"strings"
)

const listenFdsStart = 3
const resendCount = 3

var errNoMoreTries = errors.New("no more tries")

type NetConf struct {
	types.NetConf
	IPAM struct {
		Type string `json:"type,omitempty"`
		Via  string `json:"via,omitempty"`
	} `json:"ipam,omitempty"`
}

type DHCP struct {
	mux    sync.Mutex
	leases map[string]*DHCPLease
}

func newDHCP() *DHCP {
	return &DHCP{
		leases: make(map[string]*DHCPLease),
	}
}

func parseArgs(args string) (map[string]string, error) {
	result := map[string]string{}

	if args == "" {
		return nil, nil
	}

	pairs := strings.Split(args, ";")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("invalid CNI_ARGS pair %q", pair)
		}

		result[strings.ToLower(kv[0])] = kv[1]
	}

	return result, nil
}

// Allocate acquires an IP from a DHCP server for a specified container.
// The acquired lease will be maintained until Release() is called.
func (d *DHCP) Allocate(args *skel.CmdArgs, result *current.Result) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("error parsing netconf: %v", err)
	}

	parsedArgs, err := parseArgs(args.Args)
	if err != nil {
		return err
	}

	var mac net.HardwareAddr
	var client netlink.Link
	var via netlink.Link
	netns := args.Netns

	rawMac, macSupplied := parsedArgs["mac"]
	viaName := conf.IPAM.Via
	viaSupplied := viaName != ""

	if macSupplied != viaSupplied {
		return fmt.Errorf("Either supply 'mac' and 'via' or none.")
	}

	// This is useful, if the target device can't reach the dhcp server directly,
	// or if the target device creation is delayed until we have an IP address.
	if macSupplied && viaSupplied {
		// Use the supplied MAC instead of the MAC of args.ifName if present
		mac, err = net.ParseMAC(rawMac)
		if err != nil {
			return fmt.Errorf("error parsing supplied mac: %v", err)
		}

		// If a "via" device is specified, it is looked up in the current namespace
		netns = fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
		err = ns.WithNetNSPath(netns, func(_ ns.NetNS) error {
			via, err = netlink.LinkByName(viaName)
			if err != nil {
				return fmt.Errorf("error looking up %q: %v", viaName, err)
			}
			return nil
		})
	} else {
		err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
			client, err = netlink.LinkByName(args.IfName)
			if err != nil {
				return fmt.Errorf("error looking up %q: %v", args.IfName, err)
			}
			mac = client.Attrs().HardwareAddr
			return nil
		})
		if err != nil {
			return err
		}
		via = client
	}

	clientID := args.ContainerID + "/" + conf.Name
	l, err := AcquireLease(clientID, netns, via, client, mac)
	if err != nil {
		return err
	}

	ipn, err := l.IPNet()
	if err != nil {
		l.Stop()
		return err
	}

	d.setLease(args.ContainerID, conf.Name, l)

	result.IPs = []*current.IPConfig{{
		Version: "4",
		Address: *ipn,
		Gateway: l.Gateway(),
	}}
	result.Routes = l.Routes()

	return nil
}

// Release stops maintenance of the lease acquired in Allocate()
// and sends a release msg to the DHCP server.
func (d *DHCP) Release(args *skel.CmdArgs, reply *struct{}) error {
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("error parsing netconf: %v", err)
	}

	if l := d.getLease(args.ContainerID, conf.Name); l != nil {
		l.Stop()
	}

	return nil
}

func (d *DHCP) getLease(contID, netName string) *DHCPLease {
	d.mux.Lock()
	defer d.mux.Unlock()

	// TODO(eyakubovich): hash it to avoid collisions
	l, ok := d.leases[contID+netName]
	if !ok {
		return nil
	}
	return l
}

func (d *DHCP) setLease(contID, netName string, l *DHCPLease) {
	d.mux.Lock()
	defer d.mux.Unlock()

	// TODO(eyakubovich): hash it to avoid collisions
	d.leases[contID+netName] = l
}

func getListener() (net.Listener, error) {
	l, err := activation.Listeners(true)
	if err != nil {
		return nil, err
	}

	switch {
	case len(l) == 0:
		if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
			return nil, err
		}
		return net.Listen("unix", socketPath)

	case len(l) == 1:
		if l[0] == nil {
			return nil, fmt.Errorf("LISTEN_FDS=1 but no FD found")
		}
		return l[0], nil

	default:
		return nil, fmt.Errorf("Too many (%v) FDs passed through socket activation", len(l))
	}
}

func runDaemon(pidfilePath string) error {
	// since other goroutines (on separate threads) will change namespaces,
	// ensure the RPC server does not get scheduled onto those
	runtime.LockOSThread()

	// Write the pidfile
	if pidfilePath != "" {
		if !filepath.IsAbs(pidfilePath) {
			return fmt.Errorf("Error writing pidfile %q: path not absolute", pidfilePath)
		}
		if err := ioutil.WriteFile(pidfilePath, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
			return fmt.Errorf("Error writing pidfile %q: %v", pidfilePath, err)
		}
	}

	l, err := getListener()
	if err != nil {
		return fmt.Errorf("Error getting listener: %v", err)
	}

	dhcp := newDHCP()
	rpc.Register(dhcp)
	rpc.HandleHTTP()
	http.Serve(l, nil)
	return nil
}
