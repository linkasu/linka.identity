package installationbroker

import "context"

// InstallationContext is backend-only proof of a live installation capability.
// It is not a public response and does not grant telemetry consent.
type InstallationContext struct {
	ProductID         string `json:"-"`
	InstallationID    string `json:"-"`
	InstallationKey   string `json:"-"`
	TelemetryAudience string `json:"-"`
}

func (b *Broker) AuthenticateInstallation(ctx context.Context, credential string) (InstallationContext, error) {
	authenticated, err := b.authenticate(ctx, credential)
	if err != nil {
		return InstallationContext{}, err
	}
	return InstallationContext{
		ProductID: authenticated.productID, InstallationID: authenticated.alias.SubjectID,
		InstallationKey: authenticated.alias.OpaqueKey, TelemetryAudience: authenticated.audience,
	}, nil
}
