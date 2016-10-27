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
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/coreos/rkt/common"
	"github.com/coreos/rkt/pkg/oci"

	"github.com/coreos/go-systemd/unit"
	"github.com/hashicorp/errwrap"
)

func MutableEnv(p *oci.OCIPod) error {
	w := NewUnitWriter(p)

	w.WriteUnit(
		TargetUnitPath(p.Root, "default"),
		"failed to write default.target",
		unit.NewUnitOption("Unit", "Description", "rkt apps target"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Unit", "Requires", "systemd-journald.service"),
		unit.NewUnitOption("Unit", "After", "systemd-journald.service"),
		unit.NewUnitOption("Unit", "Before", "halt.target"),
		unit.NewUnitOption("Unit", "Conflicts", "halt.target"),
	)

	w.WriteUnit(
		ServiceUnitPath(p.Root, "prepare-app@"),
		"failed to write prepare-app service template",
		unit.NewUnitOption("Unit", "Description", "Prepare minimum environment for chrooted applications"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Unit", "OnFailureJobMode", "fail"),
		unit.NewUnitOption("Service", "Type", "oneshot"),
		unit.NewUnitOption("Service", "Restart", "no"),
		unit.NewUnitOption("Service", "ExecStart", "/prepare-app %I"),
		unit.NewUnitOption("Service", "User", "0"),
		unit.NewUnitOption("Service", "Group", "0"),
		unit.NewUnitOption("Service", "CapabilityBoundingSet", "CAP_SYS_ADMIN CAP_DAC_OVERRIDE"),
	)

	w.WriteUnit(
		TargetUnitPath(p.Root, "halt"),
		"failed to write halt target",
		unit.NewUnitOption("Unit", "Description", "Halt"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Unit", "AllowIsolate", "true"),
		unit.NewUnitOption("Unit", "Requires", "shutdown.service"),
		unit.NewUnitOption("Unit", "After", "shutdown.service"),
	)

	w.writeShutdownService(
		unit.NewUnitOption("Unit", "Description", "Pod shutdown"),
		unit.NewUnitOption("Unit", "AllowIsolate", "true"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Service", "RemainAfterExit", "yes"),
	)

	return w.Error()
}

// UnitWriter is the type that writes systemd units preserving the first previously occured error.
// Any method of this type can be invoked multiple times without error checking.
// If a previous invocation generated an error, any invoked method will be skipped.
// If an error occured during method invocations, it can be retrieved using Error().
type UnitWriter struct {
	err error
	p   *oci.OCIPod
}

// NewUnitWriter returns a new UnitWriter for the given pod.
func NewUnitWriter(p *oci.OCIPod) *UnitWriter {
	return &UnitWriter{p: p}
}

// WriteUnit writes a systemd unit in the given path with the given unit options
// if no previous error occured.
func (uw *UnitWriter) WriteUnit(path string, errmsg string, opts ...*unit.UnitOption) {
	if uw.err != nil {
		return
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		uw.err = errwrap.Wrap(errors.New(errmsg), err)
		return
	}
	defer file.Close()

	if _, err = io.Copy(file, unit.Serialize(opts)); err != nil {
		uw.err = errwrap.Wrap(errors.New(errmsg), err)
	}
}

// writeShutdownService writes a shutdown.service unit with the given unit options
// if no previous error occured.
// exec specifies how systemctl should be invoked, i.e. ExecStart, or ExecStop.
func (uw *UnitWriter) writeShutdownService(opts ...*unit.UnitOption) {
	if uw.err != nil {
		return
	}

	opts = append(opts, []*unit.UnitOption{
		// The default stdout is /dev/console (the tty created by nspawn).
		// But the tty might be destroyed if rkt is executed via ssh and
		// the user terminates the ssh session. We still want
		// shutdown.service to succeed in that case, so don't use
		// /dev/console.
		unit.NewUnitOption("Service", "StandardInput", "null"),
		unit.NewUnitOption("Service", "StandardOutput", "null"),
		unit.NewUnitOption("Service", "StandardError", "null"),
		unit.NewUnitOption("Service", "ExecStart", "/usr/bin/systemctl --force exit"),
	}...)

	uw.WriteUnit(
		ServiceUnitPath(uw.p.Root, "shutdown"),
		"failed to create shutdown service",
		opts...,
	)
}

// Activate actives the given unit in the given wantPath.
func (uw *UnitWriter) Activate(unit, wantPath string) {
	if uw.err != nil {
		return
	}

	if err := os.Symlink(path.Join("..", unit), wantPath); err != nil && !os.IsExist(err) {
		uw.err = errwrap.Wrap(errors.New("failed to link service want"), err)
	}
}

// error returns the first error that occured during write* invocations.
func (uw *UnitWriter) Error() error {
	return uw.err
}

func (uw *UnitWriter) AppUnit(appName string, opts ...*unit.UnitOption) {
	if uw.err != nil {
		return
	}

	absRoot, err := filepath.Abs(uw.p.Root) // Absolute path to the pod's rootfs.
	if err != nil {
		uw.err = err
		return
	}
	appBundleRoot := filepath.Join(common.AppsPath(absRoot), appName)
	runcName := uw.p.UUID + "-" + appName
	execStartString := fmt.Sprintf("/usr/bin/runc run --bundle %v %v", appBundleRoot, runcName)
	opts = append(opts, []*unit.UnitOption{
		unit.NewUnitOption("Unit", "Description", fmt.Sprintf("Application=%v", appName)),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Service", "Restart", "no"),
		unit.NewUnitOption("Service", "ExecStart", execStartString),

		// This helps working around a race
		// (https://github.com/systemd/systemd/issues/2913) that causes the
		// systemd unit name not getting written to the journal if the unit is
		// short-lived and runs as non-root.
		unit.NewUnitOption("Service", "SyslogIdentifier", appName),
	}...)

	//opts = append(opts, unit.NewUnitOption("Unit", "Requires", InstantiatedPrepareAppUnitName(appName)))
	//opts = append(opts, unit.NewUnitOption("Unit", "After", InstantiatedPrepareAppUnitName(appName)))
	//opts = append(opts, unit.NewUnitOption("Unit", "Requires", "sysusers.service"))
	//opts = append(opts, unit.NewUnitOption("Unit", "After", "sysusers.service"))

	log.Printf("writing unit file: %v", appName)
	uw.WriteUnit(ServiceUnitPath(uw.p.Root, appName), "failed to create service unit file", opts...)
	uw.Activate(ServiceUnitName(appName), ServiceWantPath(uw.p.Root, appName))
}
