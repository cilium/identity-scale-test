// Copyright 2018 Authors of Cilium
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
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	hostname       string
	kvStoreOpts    = make(map[string]string)
	statusInterval time.Duration

	rootCmd = &cobra.Command{
		Use:   "identity-scale-test",
		Short: "Run the cilium agent",
		Run: func(cmd *cobra.Command, args []string) {
			runTest(cmd)
		},
	}

	preIdentities = map[int64]*identity.Identity{}
	identities    = map[int64]*identity.Identity{}
	stopLoop      = make(chan struct{}, 0)
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	go func() {
		log.Info(http.ListenAndServe("localhost:6060", nil))
	}()

	formatter := &log.TextFormatter{FullTimestamp: true}
	log.SetFormatter(formatter)

	hostname := testutils.RandomRune()

	flags := rootCmd.Flags()
	flags.String("kvstore", "", "Key-value store type")
	flags.Var(option.NewNamedMapOptions("kvstore-opts", &kvStoreOpts, nil),
		"kvstore-opt", "Key-value store options")
	flags.String("node-name", hostname, "hostname to use when simulating agent")
	flags.Int64("pre-allocate", 0, "Number of identities to allocate before into maintenance phase")
	flags.Int("allocate-per-min", 50, "Number of allocations per minute during maintenance phase")
	flags.Int("status-interval", 5, "Interval in seconds to print status")

	viper.BindPFlags(flags)
}

type identityOwner struct{}

func (o *identityOwner) TriggerPolicyUpdates(force bool) *sync.WaitGroup {
	return nil
}

func (o *identityOwner) GetNodeSuffix() string {
	return hostname
}

type stats struct {
	name      string
	success   int
	errors    int
	lastReset time.Time
}

func (s *stats) reset() {
	s.lastReset = time.Now()
}

func (s *stats) statusDue() bool {
	return time.Since(s.lastReset) > statusInterval
}

func (s *stats) logStatus() {
	since := time.Since(s.lastReset)

	log.Infof("%s time-span %s success %f/s error %f/s", s.name, since.String(), float64(s.success)/since.Seconds(), float64(s.errors)/since.Seconds())
	s.success = 0
	s.errors = 0
	s.lastReset = time.Now()
}

var (
	allocs   = stats{name: "allocations"}
	releases = stats{name: "releases"}
)

func allocateIdentity(id int64, l []string, idMap map[int64]*identity.Identity) {
	lbls := labels.NewLabelsFromModel(l)
	allocatedIdentity, _, err := identity.AllocateIdentity(lbls)
	if err != nil {
		allocs.errors++
		log.WithError(err).Warning("Unable to allocate identity")
	} else {
		allocs.success++
		idMap[id] = allocatedIdentity
	}

	if allocs.statusDue() {
		allocs.logStatus()
	}
}

func releaseIdentity(id *identity.Identity) {
	if err := id.Release(); err != nil {
		releases.errors++
		log.WithError(err).Warning("Unable to release identity")
	} else {
		releases.success++
	}

	if releases.statusDue() {
		releases.logStatus()
	}
}

func preAllocate() {
	log.Info("Initializing identity allocator...")
	o := identityOwner{}
	identity.InitIdentityAllocator(&o)
	log.Info("Allocator is ready")

	allocs.reset()
	releases.reset()
	numAllocate := viper.GetInt64("pre-allocate")
	log.Infof("Pre-allocating %d identities...", numAllocate)
	for i := int64(0); i < numAllocate; i++ {
		allocateIdentity(i, []string{fmt.Sprintf("id=%d", i)}, preIdentities)
	}
	allocs.logStatus()
	log.Infof("Finished pre-allocating identities")
}

func releaseAllocations(identities map[int64]*identity.Identity) {
	log.Infof("Releasing %d identities...", len(identities))
	for k, id := range identities {
		releaseIdentity(id)
		delete(identities, k)
	}

	releases.logStatus()
}

func popRandomIdentity(identities map[int64]*identity.Identity) *identity.Identity {
	// rely on map iteration order being random
	for k, id := range identities {
		delete(identities, k)
		return id
	}

	return nil
}

const (
	adjustmentInterval = time.Second
)

func maintainAllocations() {
	var (
		idGenerator    int64
		allocPerMin    = viper.GetInt("allocate-per-min")
		lastAdjustment = time.Now()
		allocs         = 0

		// Start out with an assumption of being able to roughly allocate 1000
		// identities/s
		sleepTime = time.Millisecond * 10
	)

	log.Infof("Starting to allocate %d identities per minute...", allocPerMin)

	for {
		select {
		case <-stopLoop:
			return
		default:
		}
		allocateIdentity(idGenerator, []string{fmt.Sprintf("id=%d", idGenerator)}, identities)
		idGenerator++
		allocs++

		if time.Since(lastAdjustment) >= adjustmentInterval {
			factor := float64(allocs) / float64(allocPerMin)
			sleepTime = time.Duration((float64(sleepTime.Nanoseconds()) * factor))
			lastAdjustment = time.Now()
			allocs = 0
		}

		if len(identities) > allocPerMin {
			if id := popRandomIdentity(identities); id != nil {
				releaseIdentity(id)
			}
		}

		time.Sleep(sleepTime)
	}
}

var cleanupMutex sync.Mutex

func cleanup() {
	cleanupMutex.Lock()
	releaseAllocations(preIdentities)
	releaseAllocations(identities)
	cleanupMutex.Unlock()
}

func runTest(cmd *cobra.Command) {
	log.Info("Running identity allocation scale test...")

	statusInterval = time.Duration(viper.GetInt("status-interval")) * time.Second
	if statusInterval == 0 {
		log.Fatal("status-interval cannot be 0")
	}

	kvStore := viper.GetString("kvstore")

	if err := kvstore.Setup(kvStore, kvStoreOpts); err != nil {
		addrkey := fmt.Sprintf("%s.address", kvStore)
		addr := kvStoreOpts[addrkey]
		log.WithError(err).WithFields(log.Fields{
			"kvstore": kvStore,
			"address": addr,
		}).Fatal("Unable to setup kvstore")
	}

	cleanupCh := make(chan os.Signal, 1)
	signal.Notify(cleanupCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-cleanupCh
		log.Info("Stopping...")
		stopLoop <- struct{}{}
		cleanup()
	}()

	preAllocate()
	maintainAllocations()
	cleanup()

	log.Info("Done")
}
