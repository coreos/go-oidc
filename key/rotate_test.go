package key

import (
	"reflect"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
)

func generatePrivateKeySerialFunc(t *testing.T) GeneratePrivateKeyFunc {
	var n int
	return func() (*PrivateKey, error) {
		n++
		return generatePrivateKeyStatic(t, n), nil
	}
}

func TestRotate(t *testing.T) {
	now := time.Now()
	k1 := generatePrivateKeyStatic(t, 1)
	k2 := generatePrivateKeyStatic(t, 2)
	k3 := generatePrivateKeyStatic(t, 3)

	tests := []struct {
		start *PrivateKeySet
		key   *PrivateKey
		keep  int
		exp   time.Time
		want  *PrivateKeySet
	}{
		// start with nil keys
		{
			start: nil,
			key:   k1,
			keep:  2,
			exp:   now.Add(time.Second),
			want: &PrivateKeySet{
				keys:        []*PrivateKey{k1},
				ActiveKeyID: k1.KeyID,
				expiresAt:   now.Add(time.Second),
			},
		},
		// start with zero keys
		{
			start: &PrivateKeySet{},
			key:   k1,
			keep:  2,
			exp:   now.Add(time.Second),
			want: &PrivateKeySet{
				keys:        []*PrivateKey{k1},
				ActiveKeyID: k1.KeyID,
				expiresAt:   now.Add(time.Second),
			},
		},
		// add second key
		{
			start: &PrivateKeySet{
				keys:        []*PrivateKey{k1},
				ActiveKeyID: k1.KeyID,
				expiresAt:   now,
			},
			key:  k2,
			keep: 2,
			exp:  now.Add(time.Second),
			want: &PrivateKeySet{
				keys:        []*PrivateKey{k2, k1},
				ActiveKeyID: k2.KeyID,
				expiresAt:   now.Add(time.Second),
			},
		},
		// rotate in third key
		{
			start: &PrivateKeySet{
				keys:        []*PrivateKey{k2, k1},
				ActiveKeyID: k2.KeyID,
				expiresAt:   now,
			},
			key:  k3,
			keep: 2,
			exp:  now.Add(time.Second),
			want: &PrivateKeySet{
				keys:        []*PrivateKey{k3, k2},
				ActiveKeyID: k3.KeyID,
				expiresAt:   now.Add(time.Second),
			},
		},
	}

	for i, tt := range tests {
		repo := NewPrivateKeySetRepo()
		repo.Set(tt.start)
		rotatePrivateKeys(repo, tt.key, tt.keep, tt.exp)
		got, err := repo.Get()
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(tt.want, got) {
			t.Errorf("case %d: unexpected result: want=%#v got=%#v", i, tt.want, got)
		}
	}
}

func TestPrivateKeyRotatorRun(t *testing.T) {
	fc := clockwork.NewFakeClock()
	now := fc.Now().UTC()

	k1 := generatePrivateKeyStatic(t, 1)
	k2 := generatePrivateKeyStatic(t, 2)
	k3 := generatePrivateKeyStatic(t, 3)
	k4 := generatePrivateKeyStatic(t, 4)

	kRepo := NewPrivateKeySetRepo()
	krot := NewPrivateKeyRotator(kRepo, 4*time.Second)
	krot.clock = fc
	krot.generateKey = generatePrivateKeySerialFunc(t)

	steps := []*PrivateKeySet{
		&PrivateKeySet{
			keys:        []*PrivateKey{k1},
			ActiveKeyID: k1.KeyID,
			expiresAt:   now.Add(4 * time.Second),
		},
		&PrivateKeySet{
			keys:        []*PrivateKey{k2, k1},
			ActiveKeyID: k2.KeyID,
			expiresAt:   now.Add(6 * time.Second),
		},
		&PrivateKeySet{
			keys:        []*PrivateKey{k3, k2},
			ActiveKeyID: k3.KeyID,
			expiresAt:   now.Add(8 * time.Second),
		},
		&PrivateKeySet{
			keys:        []*PrivateKey{k4, k3},
			ActiveKeyID: k4.KeyID,
			expiresAt:   now.Add(10 * time.Second),
		},
	}

	stop := krot.Run()
	defer close(stop)

	for i, st := range steps {
		// wait for the rotater to get sleepy
		fc.BlockUntil(1)

		got, err := kRepo.Get()
		if err != nil {
			t.Fatalf("step %d: unexpected error: %v", i, err)
		}
		if !reflect.DeepEqual(st, got) {
			t.Fatalf("step %d: unexpected state: want=%#v got=%#v", i, st, got)
		}
		fc.Advance(2 * time.Second)
	}
}

func TestPrivateKeyRotatorExpiresAt(t *testing.T) {
	fc := clockwork.NewFakeClock()
	krot := &PrivateKeyRotator{
		clock: fc,
		ttl:   time.Minute,
	}
	got := krot.expiresAt()
	want := fc.Now().UTC().Add(time.Minute)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Incorrect expiration time: want=%v got=%v", want, got)
	}
}

func TestShouldRotate(t *testing.T) {
	fc := clockwork.NewFakeClock()
	now := fc.Now().UTC()

	tests := []struct {
		expiresAt time.Time
		ttl       time.Duration
		numKeys   int
		expected  bool
	}{
		{
			expiresAt: now.Add(time.Hour * 2),
			ttl:       time.Hour * 4,
			numKeys:   2,
			expected:  false,
		},
		{
			// No keys.
			expiresAt: now.Add(time.Hour * 2),
			ttl:       time.Hour * 4,
			numKeys:   0,
			expected:  true,
		},
		{
			// Nil keyset.
			expiresAt: now.Add(time.Hour * 2),
			ttl:       time.Hour * 4,
			numKeys:   -1,
			expected:  true,
		},
		{
			// KeySet expired.
			expiresAt: now.Add(time.Hour * -2),
			ttl:       time.Hour * 4,
			numKeys:   2,
			expected:  true,
		},
		{
			// Expiry past now + TTL
			expiresAt: now.Add(time.Hour * 5),
			ttl:       time.Hour * 4,
			numKeys:   2,
			expected:  true,
		},
	}

	for i, tt := range tests {
		kRepo := NewPrivateKeySetRepo()
		krot := NewPrivateKeyRotator(kRepo, tt.ttl)
		krot.clock = fc
		pks := &PrivateKeySet{
			expiresAt: tt.expiresAt,
		}
		if tt.numKeys != -1 {
			for n := 0; n < tt.numKeys; n++ {
				pks.keys = append(pks.keys, generatePrivateKeyStatic(t, n))
			}
			kRepo.Set(pks)
		}
		actual, err := krot.shouldRotate()
		if err != nil {
			t.Errorf("case %d: error calling shouldRotate(): %v", i, err)
		}
		if actual != tt.expected {
			t.Errorf("case %d: actual == %v, want %v", i, actual, tt.expected)
		}
	}
}
