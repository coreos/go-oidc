package key

import (
	"errors"
	"fmt"
	"time"

	"github.com/coreos/pkg/capnslog"
	"github.com/jonboulle/clockwork"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/go-oidc", "key")
)

func NewPrivateKeyRotator(repo PrivateKeySetRepo, ttl time.Duration) *PrivateKeyRotator {
	return &PrivateKeyRotator{
		repo: repo,
		ttl:  ttl,

		keep:        2,
		generateKey: GeneratePrivateKey,
		clock:       clockwork.NewRealClock(),
	}
}

type PrivateKeyRotator struct {
	repo        PrivateKeySetRepo
	generateKey GeneratePrivateKeyFunc
	clock       clockwork.Clock
	keep        int
	ttl         time.Duration
}

func (r *PrivateKeyRotator) expiresAt() time.Time {
	return r.clock.Now().UTC().Add(r.ttl)
}

func (r *PrivateKeyRotator) Run() chan struct{} {
	attempt := func() {
		k, err := r.generateKey()
		if err != nil {
			log.Errorf("Failed generating signing key: %v", err)
			return
		}

		exp := r.expiresAt()
		if err := rotatePrivateKeys(r.repo, k, r.keep, exp); err != nil {
			log.Errorf("Failed key rotation: %v", err)
			return
		}

		log.Infof("Rotated signing keys: id=%s expiresAt=%s", k.ID(), exp)
	}

	shouldRotate, err := r.shouldRotate()
	if err != nil {
		log.Errorf("failed to determine if keys should be rotated: %v", err)
	} else if shouldRotate {
		attempt()
	}

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-r.clock.After(r.ttl / 2):
				attempt()
			case <-stop:
				return
			}
		}
	}()

	return stop
}

// shouldRotate returns true when the keys need to be rotated.
// The following cases are handled:
//  - The current time is after the expiration time of the KeySet.
//  - The expiration time is after the current time + TTL;
//    this can happen when the TTL has been shortened.
//  - There are no keys in the current KeySet
func (r *PrivateKeyRotator) shouldRotate() (bool, error) {
	ks, err := r.repo.Get()
	if err == ErrorNoKeys {
		return true, nil
	}

	if err != nil {
		return false, fmt.Errorf("failed to get keyset from repo: %v", err)
	}
	pks, ok := ks.(*PrivateKeySet)
	if !ok {
		return false, errors.New("unable to cast to PrivateKeySet")
	}

	expiresAt := pks.ExpiresAt()
	now := r.clock.Now()
	shouldRotate := now.After(expiresAt) || expiresAt.After(now.Add(r.ttl)) || len(pks.Keys()) == 0
	return shouldRotate, nil
}

func rotatePrivateKeys(repo PrivateKeySetRepo, k *PrivateKey, keep int, exp time.Time) error {
	ks, err := repo.Get()
	if err != nil && err != ErrorNoKeys {
		return err
	}

	var keys []*PrivateKey
	if ks != nil {
		pks, ok := ks.(*PrivateKeySet)
		if !ok {
			return errors.New("unable to cast to PrivateKeySet")
		}
		keys = pks.Keys()
	}

	keys = append([]*PrivateKey{k}, keys...)
	if l := len(keys); l > keep {
		keys = keys[0:keep]
	}

	nks := PrivateKeySet{
		keys:        keys,
		ActiveKeyID: k.ID(),
		expiresAt:   exp,
	}

	return repo.Set(KeySet(&nks))
}
