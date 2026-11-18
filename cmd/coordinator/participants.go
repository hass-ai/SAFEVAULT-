package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sort"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "safevault/proto"
)

// nodeParticipant pilote le renouvellement d'un nœud par son service Epoch.
// Le coordinateur se présente avec son certificat "coordinator" (mTLS) : c'est ce qui
// autorise le nœud à exécuter Prepare, Commit et Abort.
type nodeParticipant struct {
	x       uint32
	address string
	tls     *tls.Config

	// Même ensemble de participants et même seuil pour tous les nœuds : sinon leurs
	// nouvelles parts ne seraient plus sur un même polynôme.
	t            uint32
	participants []*pb.Participant
}

// newNodeParticipants crée un participant par nœud configuré.
func newNodeParticipants(nodes map[uint32]string, t uint32, cert tls.Certificate, ca *x509.CertPool) []participant {
	config := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: ca, MinVersion: tls.VersionTLS13}

	var roster []*pb.Participant
	for x, address := range nodes {
		roster = append(roster, &pb.Participant{X: x, Address: address})
	}
	sort.Slice(roster, func(i, j int) bool { return roster[i].X < roster[j].X })

	participants := make([]participant, 0, len(roster))
	for _, p := range roster {
		participants = append(participants, &nodeParticipant{
			x: p.X, address: p.Address, tls: config, t: t, participants: roster,
		})
	}
	return participants
}

func (p *nodeParticipant) X() uint32 { return p.x }

func (p *nodeParticipant) Prepare(ctx context.Context, epoch uint64) error {
	return p.call(func(client pb.EpochClient) error {
		_, err := client.Prepare(ctx, &pb.PrepareRequest{Epoch: epoch, T: p.t, Participants: p.participants})
		return err
	})
}

func (p *nodeParticipant) Commit(ctx context.Context, epoch uint64) error {
	return p.call(func(client pb.EpochClient) error {
		_, err := client.Commit(ctx, &pb.EpochRequest{Epoch: epoch})
		return err
	})
}

func (p *nodeParticipant) Abort(ctx context.Context, epoch uint64) error {
	return p.call(func(client pb.EpochClient) error {
		_, err := client.Abort(ctx, &pb.EpochRequest{Epoch: epoch})
		return err
	})
}

func (p *nodeParticipant) call(f func(pb.EpochClient) error) error {
	conn, err := grpc.NewClient(p.address, grpc.WithTransportCredentials(credentials.NewTLS(p.tls.Clone())))
	if err != nil {
		return err
	}
	defer conn.Close()
	return f(pb.NewEpochClient(conn))
}
