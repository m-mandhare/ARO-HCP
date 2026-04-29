// Copyright 2026 Microsoft Corporation
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

package cachedreader

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	utilsclock "k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	azureclient "github.com/Azure/ARO-HCP/backend/pkg/azure/client"
)

func roleDefByIDResponse(id string) armauthorization.RoleDefinitionsClientGetByIDResponse {
	return armauthorization.RoleDefinitionsClientGetByIDResponse{
		RoleDefinition: armauthorization.RoleDefinition{
			ID: ptr.To(id),
			Properties: &armauthorization.RoleDefinitionProperties{
				RoleName: ptr.To("Reader"),
			},
		},
	}
}

func TestNewRoleDefinitionsCachedReader_GetCachedByID(t *testing.T) {
	ctx := context.Background()
	rid := "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
	otherRID := "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"

	tests := []struct {
		name string
		run  func(t *testing.T, ctx context.Context, rid string, otherRID string)
	}{
		{
			name: "caches successful GetByID",
			run: func(t *testing.T, ctx context.Context, rid string, _ string) {
				ctrl := gomock.NewController(t)
				want := roleDefByIDResponse(rid)
				mockClient := azureclient.NewMockRoleDefinitionsClient(ctrl)
				mockClient.EXPECT().GetByID(gomock.Any(), rid, nil).Return(want, nil).Times(1)
				r := newRoleDefinitionsCachedReader(mockClient, utilsclock.RealClock{})

				for range 2 {
					got, err := r.GetCachedByID(ctx, rid, nil)
					require.NoError(t, err)
					assert.Equal(t, want, got)
				}
			},
		},
		{
			name: "propagates inner error",
			run: func(t *testing.T, ctx context.Context, rid string, _ string) {
				ctrl := gomock.NewController(t)
				inner := errors.New("azure unavailable")
				mockClient := azureclient.NewMockRoleDefinitionsClient(ctrl)
				mockClient.EXPECT().GetByID(gomock.Any(), rid, nil).Return(armauthorization.RoleDefinitionsClientGetByIDResponse{}, inner).Times(1)
				r := newRoleDefinitionsCachedReader(mockClient, utilsclock.RealClock{})

				_, err := r.GetCachedByID(ctx, rid, nil)
				require.Error(t, err)
				assert.ErrorIs(t, err, inner)
				assert.ErrorContains(t, err, rid)
			},
		},
		{
			name: "error is not cached; next call retries",
			run: func(t *testing.T, ctx context.Context, rid string, _ string) {
				ctrl := gomock.NewController(t)
				want := roleDefByIDResponse(rid)
				mockClient := azureclient.NewMockRoleDefinitionsClient(ctrl)
				mockClient.EXPECT().GetByID(gomock.Any(), rid, nil).Return(armauthorization.RoleDefinitionsClientGetByIDResponse{}, errors.New("temporary")).Times(1)
				mockClient.EXPECT().GetByID(gomock.Any(), rid, nil).Return(want, nil).Times(1)
				r := newRoleDefinitionsCachedReader(mockClient, utilsclock.RealClock{})

				_, err := r.GetCachedByID(ctx, rid, nil)
				require.Error(t, err)

				got, err := r.GetCachedByID(ctx, rid, nil)
				require.NoError(t, err)
				assert.Equal(t, want, got)
			},
		},
		{
			name: "refreshes expired cache entry from inner client",
			run: func(t *testing.T, ctx context.Context, rid string, _ string) {
				ctrl := gomock.NewController(t)
				initial := roleDefByIDResponse(rid)
				refreshed := roleDefByIDResponse(rid)
				refreshed.Properties.RoleName = ptr.To("Contributor")
				mockClient := azureclient.NewMockRoleDefinitionsClient(ctrl)
				mockClient.EXPECT().GetByID(gomock.Any(), rid, nil).Return(initial, nil).Times(1)
				mockClient.EXPECT().GetByID(gomock.Any(), rid, nil).Return(refreshed, nil).Times(1)

				start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				fakeClock := clocktesting.NewFakePassiveClock(start)
				r := newRoleDefinitionsCachedReader(mockClient, fakeClock)

				got, err := r.GetCachedByID(ctx, rid, nil)
				require.NoError(t, err)
				assert.Equal(t, initial, got)

				fakeClock.SetTime(start.Add(roleDefinitionResourceIDCacheKeyTTL + time.Second))

				got, err = r.GetCachedByID(ctx, rid, nil)
				require.NoError(t, err)
				assert.Equal(t, refreshed, got)
			},
		},
		{
			name: "returns correct entry when multiple role definitions are cached",
			run: func(t *testing.T, ctx context.Context, rid string, otherRID string) {
				ctrl := gomock.NewController(t)
				first := roleDefByIDResponse(rid)
				second := roleDefByIDResponse(otherRID)
				mockClient := azureclient.NewMockRoleDefinitionsClient(ctrl)
				mockClient.EXPECT().GetByID(gomock.Any(), rid, nil).Return(first, nil).Times(1)
				mockClient.EXPECT().GetByID(gomock.Any(), otherRID, nil).Return(second, nil).Times(1)
				r := newRoleDefinitionsCachedReader(mockClient, utilsclock.RealClock{})

				got, err := r.GetCachedByID(ctx, rid, nil)
				require.NoError(t, err)
				assert.Equal(t, first, got)

				got, err = r.GetCachedByID(ctx, otherRID, nil)
				require.NoError(t, err)
				assert.Equal(t, second, got)

				got, err = r.GetCachedByID(ctx, rid, nil)
				require.NoError(t, err)
				assert.Equal(t, first, got)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t, ctx, rid, otherRID)
		})
	}
}
