// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"sync"
	"encoding/csv"
	"os"
	"strings"

	"github.com/omec-project/gnbsim/common"
	gnbctx "github.com/omec-project/gnbsim/gnodeb/context"
	"github.com/omec-project/gnbsim/logger"
	profctx "github.com/omec-project/gnbsim/profile/context"
	realuectx "github.com/omec-project/gnbsim/realue/context"
	"github.com/omec-project/nas/v2/security"
	"go.uber.org/zap"
)

func init() {
	simUeTable = make(map[string]*SimUe)

	CustomCredentials = make(map[string]UeCredentials)
	
	// Read custom credentials from file
	credFile := "custom_credentials.csv"
	file, err := os.Open(credFile)
	if err == nil {
		defer file.Close()
		reader := csv.NewReader(file)
		records, err := reader.ReadAll()
		if err == nil {
			for _, record := range records {
				if len(record) >= 3 {
					imsi := "imsi-" + strings.TrimSpace(record[0])
					key := strings.TrimSpace(record[1])
					opc := strings.TrimSpace(record[2])
					CustomCredentials[imsi] = UeCredentials{Key: key, OpC: opc}
				}
			}
			logger.AppLog.Infoln("Custom credentials loaded from file:", credFile)
		} else {
			logger.AppLog.Errorf("Error reading custom credentials from file %s: %v", credFile, err)
		}
	} else {
		logger.AppLog.Warnf("Custom credentials file %s not found. Proceeding without custom credentials.", credFile)
	}
}


// SimUe controls the flow of messages between RealUe and GnbUe as per the test
// profile. It is the central entry point for all events
type SimUe struct {
	GnB        *gnbctx.GNodeB
	RealUe     *realuectx.RealUe
	ProfileCtx *profctx.Profile
	Log        *zap.SugaredLogger

	// SimUe writes messages to Profile routine on this channel
	WriteProfileChan chan *common.ProfileMessage

	// SimUe writes messages to RealUE on this channel
	WriteRealUeChan chan common.InterfaceMessage

	// SimUe writes messages to GnbUE on this channel
	WriteGnbUeChan chan common.InterfaceMessage

	// SimUe reads messages from other entities on this channel
	// Entities can be RealUe, GnbUe etc.
	ReadChan chan common.InterfaceMessage

	// Message response received
	MsgRspReceived chan bool

	Supi      string
	Procedure common.ProcedureType
	WaitGrp   sync.WaitGroup
}

var (
	simUeTable      map[string]*SimUe
	simUeTableMutex sync.RWMutex
)

type UeCredentials struct {
	Key  string
	OpC  string
}

var CustomCredentials = make(map[string]UeCredentials)

func NewSimUe(supi string, gnb *gnbctx.GNodeB, profile *profctx.Profile, result chan *common.ProfileMessage) *SimUe {
	simue := SimUe{}
	simue.GnB = gnb
	simue.Supi = supi
	simue.ProfileCtx = profile
	simue.ReadChan = make(chan common.InterfaceMessage, 5)

	simue.Log = logger.SimUeLog.With(logger.FieldSupi, supi)

	ueKey := profile.Key
	ueOpc := profile.Opc
	if creds, found := CustomCredentials[supi]; found {
		ueKey = creds.Key
		ueOpc = creds.OpC
		simue.Log.Infof("Using custom credentials for SUPI %s: Key=%s, OpC=%s", supi, ueKey, ueOpc)
	}

	simue.RealUe = realuectx.NewRealUe(supi,
		security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		simue.ReadChan, profile.Plmn, ueKey, ueOpc, profile.SeqNum,
		profile.Dnn, profile.SNssai)
	simue.WriteRealUeChan = simue.RealUe.ReadChan
	simue.WriteProfileChan = result



	simue.Log.Debugln("created new SimUe context")
	simue.MsgRspReceived = make(chan bool, 5)
	simUeTableMutex.Lock()
	defer simUeTableMutex.Unlock()
	simUeTable[supi] = &simue
	return &simue
}

func GetSimUe(supi string) *SimUe {
	simUeTableMutex.RLock()
	defer simUeTableMutex.RUnlock()
	simue, found := simUeTable[supi]
	if !found {
		return nil
	}
	return simue
}
