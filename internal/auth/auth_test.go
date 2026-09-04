package auth

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func validIdentity() Identity {
	return Identity{
		Role:            RoleCoordinator,
		HomeID:          "home-1",
		ID:              "home-1",
		ClientID:        "client-1",
		CoordinatorName: "automation",
		ExpiresAt:       time.Now().Add(time.Minute),
	}
}

func TestValidateBindingRejectsPrincipalChanges(t *testing.T) {
	request := Request{
		Role:            RoleCoordinator,
		HomeID:          "home-1",
		CoordinatorName: "automation",
	}
	tests := []struct {
		name   string
		mutate func(*Identity)
		kind   ErrorKind
	}{
		{name: "role", mutate: func(identity *Identity) { identity.Role = RoleCLI }, kind: ErrRejected},
		{name: "home", mutate: func(identity *Identity) { identity.HomeID = "home-2" }, kind: ErrRejected},
		{name: "coordinator", mutate: func(identity *Identity) { identity.CoordinatorName = "other" }, kind: ErrRejected},
		{name: "long ID", mutate: func(identity *Identity) { identity.ID = strings.Repeat("x", 129) }, kind: ErrRejected},
		{name: "missing client", mutate: func(identity *Identity) { identity.ClientID = "" }, kind: ErrRejected},
		{name: "control character", mutate: func(identity *Identity) { identity.ID = "home\n1" }, kind: ErrRejected},
		{name: "invalid email", mutate: func(identity *Identity) { identity.VerifiedEmail = "user\x00@example.test" }, kind: ErrRejected},
		{name: "unrepresentable expiry", mutate: func(identity *Identity) { identity.ExpiresAt = time.UnixMilli(9_007_199_254_740_992) }, kind: ErrRejected},
		{name: "expiry", mutate: func(identity *Identity) { identity.ExpiresAt = time.Now().Add(-time.Second) }, kind: ErrExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := validIdentity()
			test.mutate(&identity)
			err := ValidateBinding(request, identity, time.Now())
			if err == nil || Kind(err) != test.kind {
				t.Fatalf("expected %s failure, received %v", test.kind, err)
			}
		})
	}
}

func TestFailureRedactsWrappedError(t *testing.T) {
	err := Failure(ErrRejected, errors.New("Bearer secret-token"))
	if err.Error() != "authentication rejected" {
		t.Fatalf("authentication error leaked its cause: %q", err.Error())
	}
	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), "secret-token") {
		t.Fatalf("serialized authentication error leaked its cause: %s", encoded)
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("authentication error exposed its wrapped cause")
	}
}

func TestPrincipalContainsOnlyVerifiedFields(t *testing.T) {
	identity := validIdentity()
	principal := identity.Principal(41)
	if principal[0] != int64(RoleCoordinator) || principal[1] != "home-1" || principal[2] != int64(41) {
		t.Fatalf("unexpected principal tuple: %#v", principal)
	}
	if principal[3] != "automation" || principal[4] != nil {
		t.Fatalf("unexpected coordinator metadata: %#v", principal)
	}
}
