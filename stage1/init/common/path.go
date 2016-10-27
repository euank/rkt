// Copyright 2014 The rkt Authors
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

//+build linux

package common

import (
	"path/filepath"

	"github.com/coreos/rkt/common"
)

const (
	// UnitsDir is the default path to systemd systemd unit directory
	UnitsDir        = "/usr/lib/systemd/system"
	envDir          = "/rkt/env" // TODO(vc): perhaps this doesn't belong in /rkt?
	defaultWantsDir = UnitsDir + "/default.target.wants"
	socketsWantsDir = UnitsDir + "/sockets.target.wants"
)

// ServiceUnitName returns a systemd service unit name for the given app name.
func ServiceUnitName(appName string) string {
	return appName + ".service"
}

// ServiceUnitPath returns the path to the systemd service file for the given
// app name.
func ServiceUnitPath(root string, appName string) string {
	return filepath.Join(common.Stage1RootfsPath(root), UnitsDir, ServiceUnitName(appName))
}

// ServiceUnitPath returns the path to the systemd service file for the given
// app name.
func TargetUnitPath(root string, name string) string {
	return filepath.Join(common.Stage1RootfsPath(root), UnitsDir, name+".target")
}

// RelEnvFilePath returns the path to the environment file for the given
// app name relative to the pod's root.
func RelEnvFilePath(appName string) string {
	return filepath.Join(envDir, appName)
}

// ServiceWantPath returns the systemd default.target want symlink path for the
// given app name.
func ServiceWantPath(root string, appName string) string {
	return filepath.Join(common.Stage1RootfsPath(root), defaultWantsDir, ServiceUnitName(appName))
}

// SocketUnitName returns a systemd socket unit name for the given app name.
func SocketUnitName(appName string) string {
	return appName + ".socket"
}

// SocketUnitPath returns the path to the systemd socket file for the given app name.
func SocketUnitPath(root string, appName string) string {
	return filepath.Join(common.Stage1RootfsPath(root), UnitsDir, SocketUnitName(appName))
}

// SocketWantPath returns the systemd sockets.target.wants symlink path for the
// given app name.
func SocketWantPath(root string, appName string) string {
	return filepath.Join(common.Stage1RootfsPath(root), socketsWantsDir, SocketUnitName(appName))
}
