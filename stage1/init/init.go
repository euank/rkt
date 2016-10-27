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

package main

// this implements /init of stage1/nspawn+systemd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/appc/goaci/proj2aci"
	"github.com/coreos/go-systemd/util"
	"github.com/coreos/pkg/dlopen"
	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"
	"github.com/hashicorp/errwrap"

	stage1common "github.com/coreos/rkt/stage1/common"
	stage1commontypes "github.com/coreos/rkt/stage1/common/types"
	stage1initcommon "github.com/coreos/rkt/stage1/init/common"

	"github.com/coreos/rkt/common"
	"github.com/coreos/rkt/common/cgroup"
	"github.com/coreos/rkt/common/cgroup/v1"
	"github.com/coreos/rkt/common/cgroup/v2"
	"github.com/coreos/rkt/networking"
	pkgflag "github.com/coreos/rkt/pkg/flag"
	rktlog "github.com/coreos/rkt/pkg/log"
	"github.com/coreos/rkt/pkg/oci"
	"github.com/coreos/rkt/pkg/sys"
)

const (
	// Path to systemd-nspawn binary within the stage1 rootfs
	nspawnBin = "/usr/bin/systemd-nspawn"
	// Path to the localtime file/symlink in host
	localtimePath = "/etc/localtime"
)

// mirrorLocalZoneInfo tries to reproduce the /etc/localtime target in stage1/ to satisfy systemd-nspawn
func mirrorLocalZoneInfo(root string) {
	zif, err := os.Readlink(localtimePath)
	if err != nil {
		return
	}

	// On some systems /etc/localtime is a relative symlink, make it absolute
	if !filepath.IsAbs(zif) {
		zif = filepath.Join(filepath.Dir(localtimePath), zif)
		zif = filepath.Clean(zif)
	}

	src, err := os.Open(zif)
	if err != nil {
		return
	}
	defer src.Close()

	destp := filepath.Join(common.Stage1RootfsPath(root), zif)

	if err = os.MkdirAll(filepath.Dir(destp), 0755); err != nil {
		return
	}

	dest, err := os.OpenFile(destp, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer dest.Close()

	_, _ = io.Copy(dest, src)
}

var (
	debug               bool
	netList             common.NetList
	interactive         bool
	privateUsers        string
	mdsToken            string
	localhostIP         net.IP
	localConfig         string
	hostname            string
	log                 *rktlog.Logger
	diag                *rktlog.Logger
	interpBin           string // Path to the interpreter within the stage1 rootfs, set by the linker
	disableCapabilities bool
	disablePaths        bool
	disableSeccomp      bool
	dnsConfMode         *pkgflag.PairList
	mutable             bool
)

func init() {
	flag.BoolVar(&debug, "debug", false, "Run in debug mode")
	flag.Var(&netList, "net", "Setup networking")
	flag.BoolVar(&interactive, "interactive", false, "The pod is interactive")
	flag.StringVar(&privateUsers, "private-users", "", "Run within user namespace. Can be set to [=UIDBASE[:NUIDS]]")
	flag.StringVar(&mdsToken, "mds-token", "", "MDS auth token")
	flag.StringVar(&localConfig, "local-config", common.DefaultLocalConfigDir, "Local config path")
	flag.StringVar(&hostname, "hostname", "", "Hostname of the pod")
	flag.BoolVar(&disableCapabilities, "disable-capabilities-restriction", false, "Disable capability restrictions")
	flag.BoolVar(&disablePaths, "disable-paths", false, "Disable paths restrictions")
	flag.BoolVar(&disableSeccomp, "disable-seccomp", false, "Disable seccomp restrictions")
	dnsConfMode = pkgflag.MustNewPairList(map[string][]string{
		"resolv": {"host", "stage0", "none", "default"},
		"hosts":  {"host", "stage0", "default"},
	}, map[string]string{
		"resolv": "default",
		"hosts":  "default",
	})
	flag.Var(dnsConfMode, "dns-conf-mode", "DNS config file modes")
	flag.BoolVar(&mutable, "mutable", false, "Enable mutable operations on this pod, including starting an empty one")

	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()

	localhostIP = net.ParseIP("127.0.0.1")
	if localhostIP == nil {
		panic("localhost IP failed to parse")
	}
}

// machinedRegister checks if nspawn should register the pod to machined
func machinedRegister() bool {
	// machined has a D-Bus interface following versioning guidelines, see:
	// http://www.freedesktop.org/wiki/Software/systemd/machined/
	// Therefore we can just check if the D-Bus method we need exists and we
	// don't need to check the signature.
	var found int

	conn, err := dbus.SystemBus()
	if err != nil {
		return false
	}
	node, err := introspect.Call(conn.Object("org.freedesktop.machine1", "/org/freedesktop/machine1"))
	if err != nil {
		return false
	}
	for _, iface := range node.Interfaces {
		if iface.Name != "org.freedesktop.machine1.Manager" {
			continue
		}
		// machined v215 supports methods "RegisterMachine" and "CreateMachine" called by nspawn v215.
		// machined v216+ (since commit 5aa4bb) additionally supports methods "CreateMachineWithNetwork"
		// and "RegisterMachineWithNetwork", called by nspawn v216+.
		for _, method := range iface.Methods {
			if method.Name == "CreateMachineWithNetwork" || method.Name == "RegisterMachineWithNetwork" {
				found++
			}
		}
		break
	}
	return found == 2
}

func installAssets() error {
	systemctlBin, err := common.LookupPath("systemctl", os.Getenv("PATH"))
	if err != nil {
		return err
	}
	systemdSysusersBin, err := common.LookupPath("systemd-sysusers", os.Getenv("PATH"))
	if err != nil {
		return err
	}
	bashBin, err := common.LookupPath("bash", os.Getenv("PATH"))
	if err != nil {
		return err
	}
	mountBin, err := common.LookupPath("mount", os.Getenv("PATH"))
	if err != nil {
		return err
	}
	umountBin, err := common.LookupPath("umount", os.Getenv("PATH"))
	if err != nil {
		return err
	}
	// More paths could be added in that list if some Linux distributions install it in a different path
	// Note that we look in /usr/lib/... first because of the merge:
	// http://www.freedesktop.org/wiki/Software/systemd/TheCaseForTheUsrMerge/
	systemdShutdownBin, err := common.LookupPath("systemd-shutdown", "/usr/lib/systemd:/lib/systemd")
	if err != nil {
		return err
	}
	systemdBin, err := common.LookupPath("systemd", "/usr/lib/systemd:/lib/systemd")
	if err != nil {
		return err
	}
	systemdJournaldBin, err := common.LookupPath("systemd-journald", "/usr/lib/systemd:/lib/systemd")
	if err != nil {
		return err
	}

	systemdUnitsPath := "/lib/systemd/system"
	assets := []string{
		proj2aci.GetAssetString("/usr/lib/systemd/systemd", systemdBin),
		proj2aci.GetAssetString("/usr/bin/systemctl", systemctlBin),
		proj2aci.GetAssetString("/usr/bin/systemd-sysusers", systemdSysusersBin),
		proj2aci.GetAssetString("/usr/lib/systemd/systemd-journald", systemdJournaldBin),
		proj2aci.GetAssetString("/usr/bin/bash", bashBin),
		proj2aci.GetAssetString("/bin/mount", mountBin),
		proj2aci.GetAssetString("/bin/umount", umountBin),
		proj2aci.GetAssetString(fmt.Sprintf("%s/systemd-journald.service", systemdUnitsPath), fmt.Sprintf("%s/systemd-journald.service", systemdUnitsPath)),
		proj2aci.GetAssetString(fmt.Sprintf("%s/systemd-journald.socket", systemdUnitsPath), fmt.Sprintf("%s/systemd-journald.socket", systemdUnitsPath)),
		proj2aci.GetAssetString(fmt.Sprintf("%s/systemd-journald-dev-log.socket", systemdUnitsPath), fmt.Sprintf("%s/systemd-journald-dev-log.socket", systemdUnitsPath)),
		proj2aci.GetAssetString(fmt.Sprintf("%s/systemd-journald-audit.socket", systemdUnitsPath), fmt.Sprintf("%s/systemd-journald-audit.socket", systemdUnitsPath)),
		// systemd-shutdown has to be installed at the same path as on the host
		// because it depends on systemd build flag -DSYSTEMD_SHUTDOWN_BINARY_PATH=
		proj2aci.GetAssetString(systemdShutdownBin, systemdShutdownBin),
	}

	return proj2aci.PrepareAssets(assets, "./stage1/rootfs/", nil)
}

// getArgsEnv returns the nspawn or lkvm args and env according to the flavor
// as the first two return values respectively.
func getArgsEnv(p *stage1commontypes.Pod, flavor string, canMachinedRegister bool, debug bool, n *networking.Networking, insecureOptions stage1initcommon.Stage1InsecureOptions) ([]string, []string, error) {
	var args []string
	env := os.Environ()

	// We store the pod's flavor so we can later garbage collect it correctly
	if err := os.Symlink(flavor, filepath.Join(p.Root, stage1initcommon.FlavorFile)); err != nil {
		return nil, nil, errwrap.Wrap(errors.New("failed to create flavor symlink"), err)
	}

	// systemd-nspawn needs /etc/machine-id to link the container's journal
	// to the host. Since systemd-v230, /etc/machine-id is mandatory, see
	// https://github.com/systemd/systemd/commit/e01ff70a77e781734e1e73a2238af2e9bf7967a8
	mPath := filepath.Join(common.Stage1RootfsPath(p.Root), "etc", "machine-id")
	machineID := strings.Replace(p.UUID.String(), "-", "", -1)

	args = append(args, filepath.Join(common.Stage1RootfsPath(p.Root), interpBin))
	args = append(args, filepath.Join(common.Stage1RootfsPath(p.Root), nspawnBin))
	args = append(args, "--boot")             // Launch systemd in the pod
	args = append(args, "--notify-ready=yes") // From systemd v231

	if context := os.Getenv(common.EnvSELinuxContext); context != "" {
		args = append(args, fmt.Sprintf("-Z%s", context))
	}

	if context := os.Getenv(common.EnvSELinuxMountContext); context != "" {
		args = append(args, fmt.Sprintf("-L%s", context))
	}

	if canMachinedRegister {
		args = append(args, fmt.Sprintf("--register=true"))
	} else {
		args = append(args, fmt.Sprintf("--register=false"))
	}

	// use only dynamic libraries provided in the image
	// from systemd v231 there's a new internal libsystemd-shared-v231.so
	// which is present in /usr/lib/systemd
	env = append(env, "LD_LIBRARY_PATH="+
		filepath.Join(common.Stage1RootfsPath(p.Root), "usr/lib")+":"+
		filepath.Join(common.Stage1RootfsPath(p.Root), "usr/lib/systemd"))

	machineIDBytes := append([]byte(machineID), '\n')
	if err := ioutil.WriteFile(mPath, machineIDBytes, 0644); err != nil {
		log.FatalE("error writing /etc/machine-id", err)
	}

	// link journal only if the host is running systemd
	if util.IsRunningSystemd() {
		args = append(args, "--link-journal=try-guest")

		keepUnit, err := util.RunningFromSystemService()
		if err != nil {
			if err == dlopen.ErrSoNotFound {
				log.Print("warning: libsystemd not found even though systemd is running. Cgroup limits set by the environment (e.g. a systemd service) won't be enforced.")
			} else {
				return nil, nil, errwrap.Wrap(errors.New("error determining if we're running from a system service"), err)
			}
		}

		if keepUnit {
			args = append(args, "--keep-unit")
		}
	} else {
		args = append(args, "--link-journal=no")
	}

	if !debug {
		args = append(args, "--quiet")             // silence most nspawn output (log_warning is currently not covered by this)
		env = append(env, "SYSTEMD_LOG_LEVEL=err") // silence log_warning too
	}

	env = append(env, "SYSTEMD_NSPAWN_CONTAINER_SERVICE=rkt")
	// TODO (alepuccetti) remove this line when rkt will use cgroup namespace
	// If the kernel has the cgroup namespace enabled, systemd v232 will use it by default.
	// This was introduced by https://github.com/systemd/systemd/pull/3809 and it will cause
	// problems in rkt when cgns is enabled and cgroup-v1 is used. For more information see
	// https://github.com/systemd/systemd/pull/3589#discussion_r70277625.
	// The following line tells systemd-nspawn not to use cgroup namespace using the environment variable
	// introduced by https://github.com/systemd/systemd/pull/3809.
	env = append(env, "SYSTEMD_NSPAWN_USE_CGNS=no")

	if len(privateUsers) > 0 {
		args = append(args, "--private-users="+privateUsers)
	}

	nsargs, err := stage1initcommon.PodToNspawnArgs(p, insecureOptions)
	if err != nil {
		return nil, nil, errwrap.Wrap(errors.New("failed to generate nspawn args"), err)
	}
	args = append(args, nsargs...)

	// Arguments to systemd
	args = append(args, "--")
	args = append(args, "--default-standard-output=tty") // redirect all service logs straight to tty
	if !debug {
		args = append(args, "--log-target=null") // silence systemd output inside pod
		args = append(args, "--show-status=0")   // silence systemd initialization status output
	}

	return args, env, nil
}

func stage1() int {
	args := flag.Args()
	uuid := flag.Arg(0)
	if uuid == "" {
		log.Print("UUID is missing")
		return 254
	}

	root := "."
	p, err := oci.LoadPod(root, uuid)
	if err != nil {
		log.PrintE("failed to load pod", err)
		return 254
	}

	// set close-on-exec flag on RKT_LOCK_FD so it gets correctly closed when invoking
	// network plugins
	lfd, err := common.GetRktLockFD()
	if err != nil {
		log.PrintE("failed to get rkt lock fd", err)
		return 254
	}

	if err := sys.CloseOnExec(lfd, true); err != nil {
		log.PrintE("failed to set FD_CLOEXEC on rkt lock", err)
		return 254
	}

	mirrorLocalZoneInfo(p.Root)

	if err = stage1initcommon.MutableEnv(p); err != nil {
		log.Error(err)
		return 254
	}

	// create a separate mount namespace so the cgroup filesystems
	// are unmounted when exiting the pod
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		log.FatalE("error unsharing", err)
	}

	// we recursively make / a "shared and slave" so mount events from the
	// new namespace don't propagate to the host namespace but mount events
	// from the host propagate to the new namespace and are forwarded to
	// its peer group
	// See https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt
	if err := syscall.Mount("", "/", "none", syscall.MS_REC|syscall.MS_SLAVE, ""); err != nil {
		log.FatalE("error making / a slave mount", err)
	}
	if err := syscall.Mount("", "/", "none", syscall.MS_REC|syscall.MS_SHARED, ""); err != nil {
		log.FatalE("error making / a shared and slave mount", err)
	}

	unifiedCgroup, err := cgroup.IsCgroupUnified("/")
	if err != nil {
		log.FatalE("error determining cgroup version", err)
		return 254
	}

	if !unifiedCgroup {
		enabledCgroups, err := v1.GetEnabledCgroups()
		if err != nil {
			log.FatalE("error getting v1 cgroups", err)
			return 254
		}

		if err := mountHostV1Cgroups(enabledCgroups); err != nil {
			log.FatalE("couldn't mount the host v1 cgroups", err)
			return 254
		}
	}

	pid_filename := "ppid"

	if err = stage1common.WritePid(os.Getpid(), pid_filename); err != nil {
		log.Error(err)
		return 254
	}

	diag.Println(args)

	err = stage1common.WithClearedCloExec(lfd, func() error {
		return syscall.Exec(args[0], args, []string{})
	})
	if err != nil {
		log.PrintE(fmt.Sprintf("failed to execute %q", args[0]), err)
		return 254
	}

	return 0
}

func areHostV1CgroupsMounted(enabledV1Cgroups map[int][]string) bool {
	controllers := v1.GetControllerDirs(enabledV1Cgroups)
	for _, c := range controllers {
		if !v1.IsControllerMounted(c) {
			return false
		}
	}

	return true
}

// mountHostV1Cgroups mounts the host v1 cgroup hierarchy as required by
// systemd-nspawn. We need this because some distributions don't have the
// "name=systemd" cgroup or don't mount the cgroup controllers in
// "/sys/fs/cgroup", and systemd-nspawn needs this. Since this is mounted
// inside the rkt mount namespace, it doesn't affect the host.
func mountHostV1Cgroups(enabledCgroups map[int][]string) error {
	systemdControllerPath := "/sys/fs/cgroup/systemd"
	if !areHostV1CgroupsMounted(enabledCgroups) {
		mountContext := os.Getenv(common.EnvSELinuxMountContext)
		if err := v1.CreateCgroups("/", enabledCgroups, mountContext); err != nil {
			return errwrap.Wrap(errors.New("error creating host cgroups"), err)
		}
	}

	if !v1.IsControllerMounted("systemd") {
		if err := os.MkdirAll(systemdControllerPath, 0700); err != nil {
			return err
		}
		if err := syscall.Mount("cgroup", systemdControllerPath, "cgroup", 0, "none,name=systemd"); err != nil {
			return errwrap.Wrap(fmt.Errorf("error mounting name=systemd hierarchy on %q", systemdControllerPath), err)
		}
	}

	return nil
}

// mountContainerV1Cgroups mounts the cgroup controllers hierarchy in the container's
// namespace read-only, leaving the needed knobs in the subcgroup for each-app
// read-write so systemd inside stage1 can apply isolators to them
func mountContainerV1Cgroups(s1Root string, enabledCgroups map[int][]string, subcgroup string, serviceNames []string) error {
	mountContext := os.Getenv(common.EnvSELinuxMountContext)
	if err := v1.CreateCgroups(s1Root, enabledCgroups, mountContext); err != nil {
		return errwrap.Wrap(errors.New("error creating container cgroups"), err)
	}
	if err := v1.RemountCgroupsRO(s1Root, enabledCgroups, subcgroup, serviceNames); err != nil {
		return errwrap.Wrap(errors.New("error restricting container cgroups"), err)
	}

	return nil
}

func getContainerSubCgroup(machineID string, canMachinedRegister, unified bool) (string, error) {
	var subcgroup string
	fromUnit, err := util.RunningFromSystemService()
	if err != nil {
		return "", errwrap.Wrap(errors.New("could not determine if we're running from a unit file"), err)
	}
	if fromUnit {
		slice, err := util.GetRunningSlice()
		if err != nil {
			return "", errwrap.Wrap(errors.New("could not get slice name"), err)
		}
		slicePath, err := common.SliceToPath(slice)
		if err != nil {
			return "", errwrap.Wrap(errors.New("could not convert slice name to path"), err)
		}
		unit, err := util.CurrentUnitName()
		if err != nil {
			return "", errwrap.Wrap(errors.New("could not get unit name"), err)
		}
		subcgroup = filepath.Join(slicePath, unit)

		if unified {
			subcgroup = filepath.Join(subcgroup, "payload")
		}
	} else {
		escapedmID := strings.Replace(machineID, "-", "\\x2d", -1)
		machineDir := "machine-" + escapedmID + ".scope"
		if canMachinedRegister {
			// we are not in the final cgroup yet: systemd-nspawn will move us
			// to the correct cgroup later during registration so we can't
			// look it up in /proc/self/cgroup
			subcgroup = filepath.Join("machine.slice", machineDir)
		} else {
			if unified {
				var err error
				subcgroup, err = v2.GetOwnCgroupPath()
				if err != nil {
					return "", errwrap.Wrap(errors.New("could not get own v2 cgroup path"), err)
				}
			} else {
				// when registration is disabled the container will be directly
				// under the current cgroup so we can look it up in /proc/self/cgroup
				ownV1CgroupPath, err := v1.GetOwnCgroupPath("name=systemd")
				if err != nil {
					return "", errwrap.Wrap(errors.New("could not get own v1 cgroup path"), err)
				}
				// systemd-nspawn won't work if we are in the root cgroup. In addition,
				// we want all rkt instances to be in distinct cgroups. Create a
				// subcgroup and add ourselves to it.
				subcgroup = filepath.Join(ownV1CgroupPath, machineDir)
				if err := v1.JoinSubcgroup("systemd", subcgroup); err != nil {
					return "", errwrap.Wrap(fmt.Errorf("error joining %s subcgroup", ownV1CgroupPath), err)
				}
			}
		}
	}

	return subcgroup, nil
}

func main() {
	flag.Parse()

	stage1initcommon.InitDebug(debug)

	log, diag, _ = rktlog.NewLogSet("stage1", debug)
	if !debug {
		diag.SetOutput(ioutil.Discard)
	}

	// move code into stage1() helper so deferred fns get run
	os.Exit(stage1())
}
