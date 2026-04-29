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

package azurehelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/utils/ptr"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

func TestActionsFromRoleDefinition(t *testing.T) {
	tests := []struct {
		name              string
		roleDefinition    armauthorization.RoleDefinition
		expectedActions   []string
		expectError       bool
		errorContainsText string
	}{
		{
			name:              "returns error when properties is nil",
			roleDefinition:    armauthorization.RoleDefinition{ID: ptr.To("rd1")},
			expectError:       true,
			errorContainsText: "doesn't contain permissions",
		},
		{
			name: "returns error when permissions is nil",
			roleDefinition: armauthorization.RoleDefinition{
				ID: ptr.To("rd2"),
				Properties: &armauthorization.RoleDefinitionProperties{
					Permissions: nil,
				},
			},
			expectError: true,
		},
		{
			name: "collects actions from all permission entries",
			roleDefinition: armauthorization.RoleDefinition{
				ID: ptr.To("/subscriptions/sub/resource"),
				Properties: &armauthorization.RoleDefinitionProperties{
					Permissions: []*armauthorization.Permission{
						{Actions: []*string{ptr.To("Microsoft.Compute/*/read")}},
						{Actions: []*string{ptr.To("Microsoft.Network/virtualNetworks/join/action")}},
					},
				},
			},
			expectedActions: []string{
				"Microsoft.Compute/*/read",
				"Microsoft.Network/virtualNetworks/join/action",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions, err := ActionsFromRoleDefinition(tt.roleDefinition)
			if tt.expectError {
				require.Error(t, err)
				if tt.errorContainsText != "" {
					assert.ErrorContains(t, err, tt.errorContainsText)
				}
				return
			}

			require.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedActions, actions)
		})
	}
}

func TestDataActionsFromRoleDefinition(t *testing.T) {
	tests := []struct {
		name                string
		roleDefinition      armauthorization.RoleDefinition
		expectedDataActions []string
		expectError         bool
		errorContainsText   string
	}{
		{
			name:              "returns error when properties is nil",
			roleDefinition:    armauthorization.RoleDefinition{},
			expectError:       true,
			errorContainsText: "doesn't contain permissions",
		},
		{
			name: "collects data actions",
			roleDefinition: armauthorization.RoleDefinition{
				Properties: &armauthorization.RoleDefinitionProperties{
					Permissions: []*armauthorization.Permission{
						{DataActions: []*string{ptr.To("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read")}},
					},
				},
			},
			expectedDataActions: []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := DataActionsFromRoleDefinition(tt.roleDefinition)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedDataActions, data)
		})
	}
}

func TestUnionActions(t *testing.T) {
	tests := []struct {
		name            string
		roleDefinitions []armauthorization.RoleDefinition
		expectedActions []string
		expectError     bool
	}{
		{
			name: "unions and deduplicates",
			roleDefinitions: []armauthorization.RoleDefinition{
				{
					Properties: &armauthorization.RoleDefinitionProperties{
						Permissions: []*armauthorization.Permission{
							{Actions: []*string{ptr.To("a/b"), ptr.To("c/d")}},
						},
					},
				},
				{
					Properties: &armauthorization.RoleDefinitionProperties{
						Permissions: []*armauthorization.Permission{
							{Actions: []*string{ptr.To("c/d"), ptr.To("e/f")}},
						},
					},
				},
			},
			expectedActions: []string{"a/b", "c/d", "e/f"},
		},
		{
			name: "propagates error from a role definition",
			roleDefinitions: []armauthorization.RoleDefinition{
				{Properties: nil},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := UnionActions(tt.roleDefinitions)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedActions, out)
		})
	}
}

func TestUnionDataActions(t *testing.T) {
	tests := []struct {
		name                string
		roleDefinitions     []armauthorization.RoleDefinition
		expectedDataActions []string
		expectError         bool
	}{
		{
			name: "unions and deduplicates",
			roleDefinitions: []armauthorization.RoleDefinition{
				{
					Properties: &armauthorization.RoleDefinitionProperties{
						Permissions: []*armauthorization.Permission{
							{DataActions: []*string{ptr.To("action/a")}},
						},
					},
				},
				{
					Properties: &armauthorization.RoleDefinitionProperties{
						Permissions: []*armauthorization.Permission{
							{DataActions: []*string{ptr.To("action/b")}},
						},
					},
				},
			},
			expectedDataActions: []string{"action/a", "action/b"},
		},
		{
			name: "propagates error from a role definition",
			roleDefinitions: []armauthorization.RoleDefinition{
				{Properties: nil},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := UnionDataActions(tt.roleDefinitions)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedDataActions, out)
		})
	}
}
