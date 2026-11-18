package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"safevault/internal/storage"
	pb "safevault/proto"
)

const testX = 3

// testNode est un nœud lancé en TLS sur un port local, avec ses clients gRPC.
type testNode struct {
	x     uint32
	addr  string
	pki   *testPKI
	node  pb.NodeClient // client utilisateur, sans certificat
	store *storage.Store
}

// testPKI est une CA de test qui signe les certificats des composants.
type testPKI struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	pool   *x509.CertPool
	serial int64
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	ca, key := newCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &testPKI{ca: ca, caKey: key, pool: pool, serial: 1}
}

// issue signe un certificat au nom name (champ CN), valable pour 127.0.0.1, utilisable
// comme certificat serveur et client, comme ceux de scripts/gen_certs.sh.
func (p *testPKI) issue(t *testing.T, name string) tls.Certificate {
	t.Helper()
	p.serial++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(p.serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// dial ouvre une connexion TLS vers addr. Avec un certificat non nil, la connexion est
// authentifiée des deux côtés (mTLS).
func (p *testPKI) dial(t *testing.T, addr string, cert *tls.Certificate) *grpc.ClientConn {
	t.Helper()
	config := &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS13}
	if cert != nil {
		config.Certificates = []tls.Certificate{*cert}
	}
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(config)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageSize), grpc.MaxCallSendMsgSize(maxMessageSize)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// startNode lance un nœud d'abscisse testX avec sa propre CA de test.
func startNode(t *testing.T) *testNode {
	t.Helper()
	return startNodeWith(t, newPKI(t), testX)
}

// startNodeWith lance le nœud x avec un certificat "node-x" signé par la CA pki.
func startNodeWith(t *testing.T, pki *testPKI, x uint32) *testNode {
	t.Helper()
	cert := pki.issue(t, nodeName(x))

	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newGRPCServer(cert, pki.pool, newNodeServer(x, store, peerTLSConfig(cert, pki.pool)))
	go server.Serve(listener)
	t.Cleanup(server.Stop)

	addr := listener.Addr().String()
	return &testNode{x: x, addr: addr, pki: pki, node: pb.NewNodeClient(pki.dial(t, addr, nil)), store: store}
}

// renewalAs renvoie un client Renewal qui se présente avec le certificat name.
func (n *testNode) renewalAs(t *testing.T, name string) pb.RenewalClient {
	t.Helper()
	cert := n.pki.issue(t, name)
	return pb.NewRenewalClient(n.pki.dial(t, n.addr, &cert))
}

// epochAs renvoie un client Epoch qui se présente avec le certificat name.
func (n *testNode) epochAs(t *testing.T, name string) pb.EpochClient {
	t.Helper()
	cert := n.pki.issue(t, name)
	return pb.NewEpochClient(n.pki.dial(t, n.addr, &cert))
}

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA de test SafeVault"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func newUserKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// makeProof construit une preuve comme le client SafeVault, avec un horodatage donné.
func makeProof(key ed25519.PrivateKey, label string, x uint32, fileID string, epoch uint64, timestamp int64) *pb.Proof {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	message := fmt.Sprintf("%d|%s|%d|%d|%x", x, fileID, epoch, timestamp, nonce)
	data := append([]byte(label), 0)
	data = append(data, message...)
	return &pb.Proof{
		PublicKey: key.Public().(ed25519.PublicKey),
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: ed25519.Sign(key, data),
	}
}

func proof(key ed25519.PrivateKey, label string, fileID string, epoch uint64) *pb.Proof {
	return makeProof(key, label, testX, fileID, epoch, time.Now().Unix())
}

func putShare(t *testing.T, n *testNode, key ed25519.PrivateKey, fileID string, epoch uint64, value []byte) {
	t.Helper()
	_, err := n.node.PutShare(context.Background(), &pb.PutShareRequest{
		FileId: fileID,
		Share:  &pb.Share{X: testX, Value: value, Epoch: epoch},
		Proof:  proof(key, labelPutShare, fileID, epoch),
	})
	if err != nil {
		t.Fatalf("PutShare : %v", err)
	}
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("code %v (%v), attendu %v", got, err, want)
	}
}

func TestShareRoundTrip(t *testing.T) {
	n := startNode(t)
	alice := newUserKey(t)
	value := make([]byte, 32)
	rand.Read(value)

	putShare(t, n, alice, "f1", 4, value)

	resp, err := n.node.GetShare(context.Background(), &pb.GetShareRequest{
		FileId: "f1", Epoch: 4, Proof: proof(alice, labelGetShare, "f1", 4),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Share.X != testX || resp.Share.Epoch != 4 || string(resp.Share.Value) != string(value) {
		t.Fatalf("part reçue %+v", resp.Share)
	}
}

func TestGetShareWrongEpoch(t *testing.T) {
	n := startNode(t)
	alice := newUserKey(t)
	putShare(t, n, alice, "f1", 4, []byte("part"))

	_, err := n.node.GetShare(context.Background(), &pb.GetShareRequest{
		FileId: "f1", Epoch: 3, Proof: proof(alice, labelGetShare, "f1", 3),
	})
	wantCode(t, err, codes.FailedPrecondition)
}

func TestGetShareUnknownFile(t *testing.T) {
	n := startNode(t)
	alice := newUserKey(t)

	_, err := n.node.GetShare(context.Background(), &pb.GetShareRequest{
		FileId: "absent", Epoch: 1, Proof: proof(alice, labelGetShare, "absent", 1),
	})
	wantCode(t, err, codes.NotFound)
}

func TestOnlyOwnerCanAccess(t *testing.T) {
	n := startNode(t)
	alice, mallory := newUserKey(t), newUserKey(t)
	putShare(t, n, alice, "f1", 1, []byte("part"))

	_, err := n.node.GetShare(context.Background(), &pb.GetShareRequest{
		FileId: "f1", Epoch: 1, Proof: proof(mallory, labelGetShare, "f1", 1),
	})
	wantCode(t, err, codes.PermissionDenied)

	_, err = n.node.PutShare(context.Background(), &pb.PutShareRequest{
		FileId: "f1", Share: &pb.Share{X: testX, Value: []byte("écrasée"), Epoch: 1},
		Proof: proof(mallory, labelPutShare, "f1", 1),
	})
	wantCode(t, err, codes.PermissionDenied)

	stream, _ := n.node.GetBlocks(context.Background(), &pb.GetBlocksRequest{
		FileId: "f1", Proof: proof(mallory, labelGetBlocks, "f1", 0),
	})
	_, err = stream.Recv()
	wantCode(t, err, codes.PermissionDenied)
}

func TestProofRejected(t *testing.T) {
	n := startNode(t)
	alice := newUserKey(t)
	putShare(t, n, alice, "f1", 1, []byte("part"))
	now := time.Now().Unix()

	tampered := proof(alice, labelGetShare, "f1", 1)
	tampered.Signature[0] ^= 1

	cases := map[string]*pb.Proof{
		"sans preuve":         nil,
		"signature modifiée":  tampered,
		"autre appel":         proof(alice, labelPutShare, "f1", 1),
		"autre nœud":          makeProof(alice, labelGetShare, testX+1, "f1", 1, now),
		"autre fichier":       proof(alice, labelGetShare, "f2", 1),
		"autre époque":        proof(alice, labelGetShare, "f1", 2),
		"trop ancienne":       makeProof(alice, labelGetShare, testX, "f1", 1, now-600),
		"datée dans le futur": makeProof(alice, labelGetShare, testX, "f1", 1, now+600),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := n.node.GetShare(context.Background(), &pb.GetShareRequest{FileId: "f1", Epoch: 1, Proof: p})
			wantCode(t, err, codes.Unauthenticated)
		})
	}
}

func TestProofReplayRejected(t *testing.T) {
	n := startNode(t)
	alice := newUserKey(t)
	putShare(t, n, alice, "f1", 1, []byte("part"))

	p := proof(alice, labelGetShare, "f1", 1)
	req := &pb.GetShareRequest{FileId: "f1", Epoch: 1, Proof: p}
	if _, err := n.node.GetShare(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	_, err := n.node.GetShare(context.Background(), req)
	wantCode(t, err, codes.Unauthenticated)
}

func TestPutShareInvalid(t *testing.T) {
	n := startNode(t)
	alice := newUserKey(t)

	cases := map[string]*pb.PutShareRequest{
		"autre abscisse": {FileId: "f1", Share: &pb.Share{X: testX + 1, Value: []byte("p"), Epoch: 1}},
		"part vide":      {FileId: "f1", Share: &pb.Share{X: testX, Epoch: 1}},
		"sans part":      {FileId: "f1"},
		"chemin":         {FileId: "../f1", Share: &pb.Share{X: testX, Value: []byte("p"), Epoch: 1}},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			req.Proof = proof(alice, labelPutShare, req.FileId, 1)
			_, err := n.node.PutShare(context.Background(), req)
			wantCode(t, err, codes.InvalidArgument)
		})
	}
}

// putBlocks envoie les blocs produits par next jusqu'à ce qu'il renvoie nil.
func putBlocks(t *testing.T, n *testNode, key ed25519.PrivateKey, fileID string, epoch uint64,
	next func(i int) []byte) (uint32, error) {

	t.Helper()
	stream, err := n.node.PutBlocks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		data := next(i)
		if data == nil {
			break
		}
		err := stream.Send(&pb.Block{FileId: fileID, Index: uint32(i), Data: data,
			Proof: proof(key, labelPutBlocks, fileID, epoch)})
		if err != nil {
			break // l'erreur du serveur arrive avec CloseAndRecv
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return 0, err
	}
	return resp.Stored, nil
}

func TestBlocksRoundTrip(t *testing.T) {
	n := startNode(t)
	alice := newUserKey(t)
	putShare(t, n, alice, "f1", 2, []byte("part"))

	blocks := [][]byte{[]byte("bloc 0"), []byte("bloc 1"), make([]byte, 100_000)}
	rand.Read(blocks[2])
	stored, err := putBlocks(t, n, alice, "f1", 2, func(i int) []byte {
		if i < len(blocks) {
			return blocks[i]
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stored != 3 {
		t.Fatalf("%d blocs stockés, attendus 3", stored)
	}

	stream, err := n.node.GetBlocks(context.Background(), &pb.GetBlocksRequest{
		FileId: "f1", Proof: proof(alice, labelGetBlocks, "f1", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		b, err := stream.Recv()
		if err == io.EOF {
			if i != len(blocks) {
				t.Fatalf("%d blocs reçus, attendus %d", i, len(blocks))
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if b.Index != uint32(i) || string(b.Data) != string(blocks[i]) {
			t.Fatalf("bloc %d incorrect", i)
		}
	}
}

func TestPutBlocksBeforeShare(t *testing.T) {
	n := startNode(t)
	alice := newUserKey(t)

	_, err := putBlocks(t, n, alice, "f1", 1, func(i int) []byte {
		if i == 0 {
			return []byte("bloc")
		}
		return nil
	})
	wantCode(t, err, codes.FailedPrecondition)
}

func TestPutBlocksSingleFile(t *testing.T) {
	n := startNode(t)
	alice := newUserKey(t)
	putShare(t, n, alice, "f1", 1, []byte("part"))
	putShare(t, n, alice, "f2", 1, []byte("part"))

	stream, _ := n.node.PutBlocks(context.Background())
	stream.Send(&pb.Block{FileId: "f1", Index: 0, Data: []byte("a"), Proof: proof(alice, labelPutBlocks, "f1", 1)})
	stream.Send(&pb.Block{FileId: "f2", Index: 1, Data: []byte("b"), Proof: proof(alice, labelPutBlocks, "f2", 1)})
	_, err := stream.CloseAndRecv()
	wantCode(t, err, codes.InvalidArgument)
}

// TestLargeFileStreaming transfère 100 Mo et vérifie que ni l'envoi ni la lecture ne
// chargent le fichier entier en mémoire.
func TestLargeFileStreaming(t *testing.T) {
	if testing.Short() {
		t.Skip("transfert de 100 Mo ignoré en mode -short")
	}
	const blockSize = 1 << 20
	const blockCount = 100

	n := startNode(t)
	alice := newUserKey(t)
	putShare(t, n, alice, "gros", 1, []byte("part"))

	// Les blocs sont générés à la volée à partir de leur numéro.
	block := func(i int) []byte {
		data := make([]byte, blockSize)
		for j := range data {
			data[j] = byte(i + j)
		}
		return data
	}

	// Un ramasse-miettes plus fréquent pendant la mesure : sans lui, le pic compte surtout
	// des blocs déjà libérés mais pas encore récupérés, et dépend de la vitesse de la machine.
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	runtime.GC()
	var peak atomic.Uint64
	done := make(chan struct{})
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse)
				}
			}
		}
	}()

	stored, err := putBlocks(t, n, alice, "gros", 1, func(i int) []byte {
		if i < blockCount {
			return block(i)
		}
		return nil
	})
	if err != nil || stored != blockCount {
		t.Fatalf("%d blocs stockés, erreur %v", stored, err)
	}

	stream, err := n.node.GetBlocks(context.Background(), &pb.GetBlocksRequest{
		FileId: "gros", Proof: proof(alice, labelGetBlocks, "gros", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	received := 0
	for {
		b, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if sha256.Sum256(b.Data) != sha256.Sum256(block(int(b.Index))) {
			t.Fatalf("bloc %d corrompu", b.Index)
		}
		received++
	}
	close(done)

	if received != blockCount {
		t.Fatalf("%d blocs reçus, attendus %d", received, blockCount)
	}
	// Client et serveur tournent dans le même processus : charger les 100 Mo dépasserait
	// largement cette limite.
	if peak.Load() > 48<<20 {
		t.Fatalf("pic mémoire de %d Mo pendant le transfert", peak.Load()>>20)
	}
	t.Logf("100 Mo transférés, pic mémoire du tas : %d Mo", peak.Load()>>20)
}

func TestDeliverSubShares(t *testing.T) {
	n := startNode(t)
	ctx := context.Background()

	_, err := n.renewalAs(t, "node-1").DeliverSubShares(ctx, &pb.DeliverSubSharesRequest{
		FromX: 1, ToX: testX, TargetEpoch: 5,
		SubShares: []*pb.SubShare{{FileId: "f1", Value: []byte("d1")}, {FileId: "f2", Value: []byte("d2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	subs, err := n.store.SubShares(5)
	if err != nil || len(subs) != 2 || subs[0].FromX != 1 {
		t.Fatalf("sous-parts stockées %+v, erreur %v", subs, err)
	}

	cases := map[string]*pb.DeliverSubSharesRequest{
		"autre destinataire": {FromX: 1, ToX: testX + 1, TargetEpoch: 5},
		"époque nulle":       {FromX: 1, ToX: testX},
		"sous-part vide":     {FromX: 1, ToX: testX, TargetEpoch: 5, SubShares: []*pb.SubShare{{FileId: "f1"}}},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := n.renewalAs(t, "node-1").DeliverSubShares(ctx, req)
			wantCode(t, err, codes.InvalidArgument)
		})
	}
	t.Run("émetteur = soi", func(t *testing.T) {
		_, err := n.renewalAs(t, nodeName(testX)).DeliverSubShares(ctx, &pb.DeliverSubSharesRequest{FromX: testX, ToX: testX, TargetEpoch: 5})
		wantCode(t, err, codes.InvalidArgument)
	})
}

// TestDeliverSubSharesRequiresNodeCertificate vérifie que seules les sous-parts envoyées par
// le nœud annoncé sont acceptées.
func TestDeliverSubSharesRequiresNodeCertificate(t *testing.T) {
	n := startNode(t)
	req := &pb.DeliverSubSharesRequest{FromX: 1, ToX: testX, TargetEpoch: 5,
		SubShares: []*pb.SubShare{{FileId: "f1", Value: []byte("d")}}}

	_, err := pb.NewRenewalClient(n.pki.dial(t, n.addr, nil)).DeliverSubShares(context.Background(), req)
	wantCode(t, err, codes.Unauthenticated)

	_, err = n.renewalAs(t, "node-2").DeliverSubShares(context.Background(), req)
	wantCode(t, err, codes.PermissionDenied)

	// Un certificat au bon nom mais signé par une autre CA est refusé dès la poignée de main.
	other := newPKI(t)
	cert := other.issue(t, "node-1")
	config := &tls.Config{RootCAs: n.pki.pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	conn, _ := grpc.NewClient(n.addr, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	defer conn.Close()
	_, err = pb.NewRenewalClient(conn).DeliverSubShares(context.Background(), req)
	if err == nil {
		t.Fatal("certificat d'une autre CA accepté")
	}

	if subs, _ := n.store.SubShares(5); len(subs) != 0 {
		t.Fatalf("%d sous-parts enregistrées malgré les refus", len(subs))
	}
}

// TestRejectsUntrustedConnections vérifie qu'on ne parle au nœud qu'en TLS, et qu'un client
// qui ne fait pas confiance à la CA du nœud refuse la connexion.
func TestRejectsUntrustedConnections(t *testing.T) {
	n := startNode(t)
	req := &pb.GetShareRequest{FileId: "f1", Epoch: 1}

	plain, err := grpc.NewClient(n.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	_, err = pb.NewNodeClient(plain).GetShare(context.Background(), req)
	wantCode(t, err, codes.Unavailable)

	otherCA, _ := newCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(otherCA)
	creds := credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
	untrusted, err := grpc.NewClient(n.addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	_, err = pb.NewNodeClient(untrusted).GetShare(context.Background(), req)
	wantCode(t, err, codes.Unavailable)
}
