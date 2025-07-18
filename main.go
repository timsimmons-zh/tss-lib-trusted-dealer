package main

import (
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	golog "github.com/ipfs/go-log"

	tsscrypto "github.com/bnb-chain/tss-lib/v2/crypto"
	eckeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	ecresharing "github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	edkeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	edresharing "github.com/bnb-chain/tss-lib/v2/eddsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Types for channel communication
type baseResult struct {
	pid *tss.PartyID
}
type ecresult struct {
	pid  *tss.PartyID
	data eckeygen.LocalPartySaveData
}

type edresult struct {
	pid  *tss.PartyID
	data edkeygen.LocalPartySaveData
}

type msg struct {
	from *tss.PartyID
	data tss.Message
}

func main() {
	// Enable debug logging
	if err := golog.SetLogLevel("tss-lib", "debug"); err != nil {
		panic(err)
	}

	// runECDSAResharing()
	runEDDSAResharing()
}

func runECDSAResharing() {
	// 1) Define parties: importer (old group) + three co-signers (new group)
	importerParty := tss.NewPartyID("importer", "Importer", big.NewInt(0))
	signerParties := []*tss.PartyID{
		tss.NewPartyID("signer1", "Signer1", big.NewInt(1)),
		tss.NewPartyID("signer2", "Signer2", big.NewInt(2)),
		tss.NewPartyID("signer3", "Signer3", big.NewInt(3)),
	}

	allOld := tss.NewPeerContext(
		tss.SortPartyIDs([]*tss.PartyID{importerParty}),
	)
	allNew := tss.NewPeerContext(
		tss.SortPartyIDs(signerParties),
	)

	curve := tss.S256() // secp256k1

	// 2) Generate Paillier & ZK pre-params for each party
	fmt.Println("Computing local PreParams")
	preImp, _ := eckeygen.GeneratePreParams(1 * time.Minute)
	preSigners := make([]*eckeygen.LocalPreParams, 3)
	var err error
	for i := range signerParties {
		fmt.Printf("Computing local PreParams for signer %d\n", i)
		preSigners[i], err = eckeygen.GeneratePreParams(1 * time.Minute)
		if err != nil {
			msg := fmt.Sprintf("failed to generate pre-params for signer %d: %v", i, err)
			panic(msg)
		}
	}
	fmt.Println("Finished computing local PreParams")

	// Channels for messages and results

	outCh := make(chan msg, 10)
	signerEndCh := make(chan ecresult, 3)

	// Build resharing parameters: old=1-of-1, new=3-of-3 (t+1=3 ⇒ t=2)
	impParams := tss.NewReSharingParameters(
		curve,
		allOld, allNew,
		importerParty,
		1, 0,
		3, 2)

	// impParams.NoProofFac()
	// impParams.NoProofMod()

	// Importer’s save data with the full private key
	plaintextKey := big.NewInt(0xff) // ← your ECDSA private key here
	impSave := eckeygen.NewLocalPartySaveData(1)
	impSave.LocalPreParams = *preImp
	impSave.LocalSecrets = eckeygen.LocalSecrets{
		Xi:      plaintextKey,
		ShareID: importerParty.KeyInt(),
	}
	impSave.Ks[0] = importerParty.KeyInt()
	impSave.BigXj[0] = tsscrypto.ScalarBaseMult(curve, plaintextKey)
	impSave.ECDSAPub = impSave.BigXj[0]

	impSave.NTildej[0] = preImp.NTildei
	impSave.H1j[0] = preImp.H1i
	impSave.H2j[0] = preImp.H2i
	impSave.PaillierPKs[0] = &preImp.PaillierSK.PublicKey

	// Set signer's resharing parameters
	signerParams := make([]*tss.ReSharingParameters, 3)
	for i, pid := range signerParties {
		signerParams[i] = tss.NewReSharingParameters(curve, allOld, allNew,
			pid, 1, 0, 3, 2)
		// signerParams[i].NoProofFac()
		// signerParams[i].NoProofMod()
	}

	// Simple broadcast router: send each outgoing message to all other parties
	partyMap := make(map[string]*ecresharing.LocalParty)
	var importerPartyInstance *ecresharing.LocalParty
	var signerPartyInstances [3]*ecresharing.LocalParty

	// Create all parties
	discardEndCh := make(chan ecresult, 1) // importer results can be ignored
	importerPartyInstance = ecresharing.NewLocalParty(
		impParams,
		impSave,
		makeOutCh(importerParty, outCh),
		makeEcEndCh(importerParty, discardEndCh),
	).(*ecresharing.LocalParty)
	partyMap[importerParty.Id] = importerPartyInstance

	for i, pid := range signerParties {
		if pid.KeyInt().Sign() < 0 {
			panic(fmt.Sprintf("Invalid PartyID: %s has negative index %s", pid.Moniker, pid.KeyInt().String()))
		}
		fmt.Printf("PartyID: %s, Index: %s\n", pid.Moniker, pid.KeyInt().String())

		signerSave := eckeygen.NewLocalPartySaveData(1)
		signerSave.LocalPreParams = *preSigners[i]

		signerSave.Ks[0] = importerParty.KeyInt()
		signerSave.BigXj[0] = impSave.BigXj[0]
		signerSave.NTildej[0] = preImp.NTildei
		signerSave.H1j[0] = preImp.H1i
		signerSave.H2j[0] = preImp.H2i
		signerSave.PaillierPKs[0] = &preImp.PaillierSK.PublicKey

		signerPartyInstances[i] = ecresharing.NewLocalParty(
			signerParams[i],
			signerSave,
			makeOutCh(pid, outCh),
			makeEcEndCh(pid, signerEndCh),
		).(*ecresharing.LocalParty)
		partyMap[pid.Id] = signerPartyInstances[i]
	}

	var wg sync.WaitGroup

	// Launch each co-signer’s resharing party (they start with only pre-params)
	for i, pid := range signerParties {
		wg.Add(1)
		go func(i int, pid *tss.PartyID) {
			defer wg.Done()
			if err := signerPartyInstances[i].Start(); err != nil {
				panic(err)
			}
		}(i, pid)
	}

	// Launch importer’s party
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := importerPartyInstance.Start(); err != nil {
			log.Fatalf("Importer resharing party failed: %v", err)
		}
	}()

	go func() {
		for m := range outCh {
			payload, routing, err := m.data.WireBytes()
			if err != nil {
				log.Printf("Error serializing message from %s: %v", m.from.Id, err)
				continue
			}
			fmt.Printf(">>> %s sending message to all parties: %s\n", m.from.Id, m.data.Type())
			for _, to := range routing.To {
				if to.Id == m.from.Id {
					fmt.Printf("Ignoring message from self: %s\n", m.from.Id)
					continue
				}
				p := partyMap[to.Id]
				if p == nil {
					log.Printf("Party instance for %s not found", to.Id)
					continue
				}
				ok, err := p.UpdateFromBytes(payload, m.from, routing.IsBroadcast)
				if err != nil {
					log.Printf("Error updating party %s with message from %s: %v", to.Id, m.from.Id, err)
				}
				if !ok {
					log.Printf("Party %s could not process message from %s: %v", to.Id, m.from.Id, err)
				}
				fmt.Printf(">>> %s updated party %s with message\n", m.from.Id, to.Id)
			}
		}
	}()

	// Collect each signer’s new save data (their individual share + proofs)
	results := map[string]ecresult{}
	for i := 0; i < 3; i++ {
		r := <-signerEndCh
		// fmt.Printf(">>> %s completed with result: %+v\n", r.pid.Id, r.data)
		// Persist r.data securely for future signing
		results[r.pid.Id] = r
	}

	wg.Wait()

	// Add all the Xi to make sure they sum to importer's Xi
	totalXi := big.NewInt(0)
	for _, r := range results {
		totalXi.Add(totalXi, r.data.LocalSecrets.Xi)
		fmt.Printf(">>> %s completed with result: %+v\n", r.pid.Id, r.data)
		fmt.Println("--------------------------------------------------------")
		fmt.Println()
	}
	totalXi.Mod(totalXi, curve.Params().N) // Ensure it fits in the curve order
	// Verify it matches the importer's original key
	if plaintextKey.Cmp(impSave.LocalSecrets.Xi) != 0 {
		log.Fatalf("Total Xi %s does not match importer's Xi %s", totalXi, impSave.LocalSecrets.Xi)
	}
	fmt.Println(">>> All signers completed successfully. Total Xi matches.")
}

func runEDDSAResharing() {
	// 1) Define parties: importer (old group) + three co-signers (new group)
	importerParty := tss.NewPartyID("importer", "Importer", big.NewInt(0))
	signerParties := []*tss.PartyID{
		tss.NewPartyID("signer1", "Signer1", big.NewInt(1)),
		tss.NewPartyID("signer2", "Signer2", big.NewInt(2)),
		tss.NewPartyID("signer3", "Signer3", big.NewInt(3)),
	}

	allOld := tss.NewPeerContext(
		tss.SortPartyIDs([]*tss.PartyID{importerParty}),
	)
	allNew := tss.NewPeerContext(
		tss.SortPartyIDs(signerParties),
	)

	curve := tss.Edwards() // ED25519

	// Channels for messages and results
	outCh := make(chan msg, 10)
	signerEndCh := make(chan edresult, 3)

	// Build resharing parameters: old=1-of-1, new=3-of-3 (t+1=3 ⇒ t=2)
	impParams := tss.NewReSharingParameters(
		curve,
		allOld, allNew,
		importerParty,
		1, 0,
		3, 2)

	// impParams.NoProofFac()
	// impParams.NoProofMod()

	// Importer’s save data with the full private key
	plaintextKey := big.NewInt(0xff) // ← your ECDSA private key here
	impSave := edkeygen.NewLocalPartySaveData(1)
	impSave.LocalSecrets = edkeygen.LocalSecrets{
		Xi:      plaintextKey,
		ShareID: importerParty.KeyInt(),
	}
	impSave.Ks[0] = importerParty.KeyInt()
	impSave.BigXj[0] = tsscrypto.ScalarBaseMult(curve, plaintextKey)
	impSave.EDDSAPub = impSave.BigXj[0]

	// Set signer's resharing parameters
	signerParams := make([]*tss.ReSharingParameters, 3)
	for i, pid := range signerParties {
		signerParams[i] = tss.NewReSharingParameters(curve, allOld, allNew,
			pid, 1, 0, 3, 2)
	}

	// Simple broadcast router: send each outgoing message to all other parties
	partyMap := make(map[string]*edresharing.LocalParty)
	var importerPartyInstance *edresharing.LocalParty
	var signerPartyInstances [3]*edresharing.LocalParty

	// Create all parties
	discardEndCh := make(chan edresult, 1) // importer results can be ignored
	importerPartyInstance = edresharing.NewLocalParty(
		impParams,
		impSave,
		makeOutCh(importerParty, outCh),
		makeEdEndCh(importerParty, discardEndCh),
	).(*edresharing.LocalParty)
	partyMap[importerParty.Id] = importerPartyInstance

	for i, pid := range signerParties {
		if pid.KeyInt().Sign() < 0 {
			panic(fmt.Sprintf("Invalid PartyID: %s has negative index %s", pid.Moniker, pid.KeyInt().String()))
		}
		fmt.Printf("PartyID: %s, Index: %s\n", pid.Moniker, pid.KeyInt().String())

		signerSave := edkeygen.NewLocalPartySaveData(1)

		signerSave.Ks[0] = importerParty.KeyInt()
		signerSave.BigXj[0] = impSave.BigXj[0]

		signerPartyInstances[i] = edresharing.NewLocalParty(
			signerParams[i],
			signerSave,
			makeOutCh(pid, outCh),
			makeEdEndCh(pid, signerEndCh),
		).(*edresharing.LocalParty)
		partyMap[pid.Id] = signerPartyInstances[i]
	}

	var wg sync.WaitGroup

	// Launch each co-signer’s resharing party (they start with only pre-params)
	for i, pid := range signerParties {
		wg.Add(1)
		go func(i int, pid *tss.PartyID) {
			defer wg.Done()
			if err := signerPartyInstances[i].Start(); err != nil {
				panic(err)
			}
		}(i, pid)
	}

	// Launch importer’s party
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := importerPartyInstance.Start(); err != nil {
			log.Fatalf("Importer resharing party failed: %v", err)
		}
	}()

	go func() {
		for m := range outCh {
			payload, routing, err := m.data.WireBytes()
			if err != nil {
				log.Printf("Error serializing message from %s: %v", m.from.Id, err)
				continue
			}
			fmt.Printf(">>> %s sending message to all parties: %s\n", m.from.Id, m.data.Type())
			for _, to := range routing.To {
				if to.Id == m.from.Id {
					fmt.Printf("Ignoring message from self: %s\n", m.from.Id)
					continue
				}
				p := partyMap[to.Id]
				if p == nil {
					log.Printf("Party instance for %s not found", to.Id)
					continue
				}
				ok, err := p.UpdateFromBytes(payload, m.from, routing.IsBroadcast)
				if err != nil {
					log.Printf("Error updating party %s with message from %s: %v", to.Id, m.from.Id, err)
				}
				if !ok {
					log.Printf("Party %s could not process message from %s: %v", to.Id, m.from.Id, err)
				}
				fmt.Printf(">>> %s updated party %s with message\n", m.from.Id, to.Id)
			}
		}
	}()

	// Collect each signer’s new save data (their individual share + proofs)
	results := map[string]edresult{}
	for i := 0; i < 3; i++ {
		r := <-signerEndCh
		// fmt.Printf(">>> %s completed with result: %+v\n", r.pid.Id, r.data)
		// Persist r.data securely for future signing
		results[r.pid.Id] = r
	}

	wg.Wait()

	// Add all the Xi to make sure they sum to importer's Xi
	totalXi := big.NewInt(0)
	for _, r := range results {
		totalXi.Add(totalXi, r.data.LocalSecrets.Xi)
		fmt.Printf(">>> %s completed with result: %+v\n", r.pid.Id, r.data)
		fmt.Println("--------------------------------------------------------")
		fmt.Println()
	}
	totalXi.Mod(totalXi, curve.Params().N) // Ensure it fits in the curve order
	// Verify it matches the importer's original key
	if plaintextKey.Cmp(impSave.LocalSecrets.Xi) != 0 {
		log.Fatalf("Total Xi %s does not match importer's Xi %s", totalXi, impSave.LocalSecrets.Xi)
	}
	fmt.Println(">>> All signers completed successfully. Total Xi matches.")
}

// Helpers to wrap channels with party IDs
func makeOutCh(pid *tss.PartyID, outCh chan msg) chan tss.Message {
	ch := make(chan tss.Message, 10)
	go func() {
		for m := range ch {
			outCh <- msg{from: pid, data: m}
		}
	}()
	return ch
}
func makeEcEndCh(pid *tss.PartyID, endCh chan ecresult) chan *eckeygen.LocalPartySaveData {
	ch := make(chan *eckeygen.LocalPartySaveData, 1)
	go func() {
		for sd := range ch {
			endCh <- ecresult{pid: pid, data: *sd}
		}
	}()
	return ch
}

func makeEdEndCh(pid *tss.PartyID, endCh chan edresult) chan *edkeygen.LocalPartySaveData {
	ch := make(chan *edkeygen.LocalPartySaveData, 1)
	go func() {
		for sd := range ch {
			endCh <- edresult{pid: pid, data: *sd}
		}
	}()
	return ch
}
