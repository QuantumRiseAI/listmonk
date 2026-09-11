// Package azcred builds the Azure credential listmonk authenticates with.
//
// Shared rather than duplicated: both the Postgres token path and the secret
// reference resolver need the same identity, and the reasoning about which
// credential to use is the part worth having in exactly one place.
package azcred

import (
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// ResolveClientID picks the managed identity to authenticate as, preferring an
// explicit setting and falling back to AZURE_CLIENT_ID.
//
// The fallback is not a convenience. ManagedIdentityCredential does NOT read
// AZURE_CLIENT_ID — that is DefaultAzureCredential behaviour — so with neither
// set it silently resolves the host's *system-assigned* identity. A host
// carrying only user-assigned identities has none, so the failure is an
// unhelpful IMDS error rather than anything naming the cause. AZURE_CLIENT_ID
// is also the conventional way to select an identity, so honouring it is what
// makes the usual deployment work rather than fail confusingly.
func ResolveClientID(clientID string) string {
	if clientID != "" {
		return clientID
	}

	return strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID"))
}

// New builds a token credential. Managed identity is the default and the broad
// DefaultAzureCredential chain is opt-in.
func New(clientID string, useDefaultChain bool) (azcore.TokenCredential, error) {
	clientID = ResolveClientID(clientID)

	if useDefaultChain {
		// DefaultAzureCredential walks a broad chain that includes ambient
		// AZURE_* environment variables and a developer's local `az login`.
		// That is convenient on a laptop but wrong as a default for a service
		// credential: a stray AZURE_CLIENT_SECRET in the environment would
		// silently outrank the intended managed identity, and a developer
		// running the binary would authenticate as themselves rather than as
		// the app. So the narrow credential is the default and this one has to
		// be asked for by name.
		//
		// DefaultAzureCredentialOptions carries no field for a user-assigned
		// identity, so this path can only take one from AZURE_CLIENT_ID in the
		// environment. Set it from the configured value when there is one, so
		// the setting means the same thing on both paths.
		if clientID != "" {
			if err := os.Setenv("AZURE_CLIENT_ID", clientID); err != nil {
				return nil, fmt.Errorf("error setting AZURE_CLIENT_ID for the credential chain: %w", err)
			}
		}

		return azidentity.NewDefaultAzureCredential(nil)
	}

	opts := &azidentity.ManagedIdentityCredentialOptions{}
	if clientID != "" {
		opts.ID = azidentity.ClientID(clientID)
	}

	// With no ID set, this resolves the host's system-assigned identity.
	return azidentity.NewManagedIdentityCredential(opts)
}
