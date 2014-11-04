// Package bpf provides primitives for interfacing with the Berkeley Packet Filter.
package bpf

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Bpf represents a tap into a network interface
type Bpf struct {
	filepath string
	fd       int
	ifname   string
}

const (
	SizeofMacAddress = 0x06 // 6 Octets
	SizeofEtherType  = 0x02 // 2 Octets
)

type ivalue struct {
	name  [syscall.IFNAMSIZ]byte
	value int64
}

// Returns the required buffer length for reads on bpf files and any errors encountered
// while accessing the BIOCGBLEN IOCTL.
func GetBuflen(fd int) (int, error) {
	var len int
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCGBLEN, uintptr(unsafe.Pointer(&len)))
	if err != 0 {
		return 0, syscall.Errno(err)
	}
	return len, nil
}

// Sets the buffer length for reads on bpf files.  The buffer must be set before
// the file is attached to an interface with BIOCSETIF.  If the requested buffer
// size cannot e accommodated, the closest allowable size will be set and
// returned in the argument.  A read call will result in EINVAL if it is passed
// a buffer that is not this size.
func SetBpfBuflen(fd, l int) (int, error) {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSBLEN, uintptr(unsafe.Pointer(&l)))
	if err != 0 {
		return 0, syscall.Errno(err)
	}
	return l, nil
}

// Returns the type of the data link layer underlying the attached interface.
// EINVAL is returned if no interface has been specified.
func Datalink(fd int) (int, error) {
	var t int
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCGDLT, uintptr(unsafe.Pointer(&t)))
	if err != 0 {
		return 0, syscall.Errno(err)
	}
	return t, nil
}

// Returns an array of the available types of the data link layer underlying
// the attached interface:

// Changes the type of the data link layer underlying the attached interface.
// EINVAL is returned if no interface has been specified or the specified type
// is not available for the interface
func SetDatalink(fd, t int) (int, error) {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSDLT, uintptr(unsafe.Pointer(&t)))
	if err != 0 {
		return 0, syscall.Errno(err)
	}
	return t, nil
}

// Forces the interface into promiscuous mode.  All packets, not just those
// destined for the local host, are processed.  Since more than one file can be
// listening on a given interface, a listener that opened its interface
// non-promiscuously may receive packetspromiscuously.  This problem can be
// remedied with an appropriate filter.
func SetPromisc(fd, m int) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCPROMISC, uintptr(unsafe.Pointer(&m)))
	if err != 0 {
		return syscall.Errno(err)
	}
	return nil
}

// Flushes the buffer of incoming packets, and resets the statistics that are
// returned by BIOCGSTATS.
func Flush(fd int) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCFLUSH, 0)
	if err != 0 {
		return syscall.Errno(err)
	}
	return nil
}

// Returns the name of the hardware interface that the file is listening on. The
// name is returned in the ifr_name field of the ifreq structure.  All other
// fields are undefined.
func Interface(fd int, name string) (string, error) {
	var iv ivalue
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCGETIF, uintptr(unsafe.Pointer(&iv)))
	if err != 0 {
		return "", syscall.Errno(err)
	}
	return name, nil
}

// Sets the hardware interface associated with the file.  This command must be
// performed before any packets can be read.  The device is indicated by name
// using the name field of the ivalue struct.  Additionally, performs the
// actions of BIOCFLUSH
func SetInterface(fd int, name string) error {
	var iv ivalue
	copy(iv.name[:], []byte(name))
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSETIF, uintptr(unsafe.Pointer(&iv)))
	if err != 0 {
		return syscall.Errno(err)
	}
	return nil
}

// Get the read timeout parameter.  The argument specifies the length
// of time to wait before timing out on a read request.  This parameter is
// initializedized to zero by os.Open(2), indicating no timeout.
func GetTimeout(fd int) (*syscall.Timeval, error) {
	var tv syscall.Timeval
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCGRTIMEOUT, uintptr(unsafe.Pointer(&tv)))
	if err != 0 {
		return nil, syscall.Errno(err)
	}
	return &tv, nil
}

// Sets the read timeout parameter.  The argument specifies the length
// of time to wait before timing out on a read request.  This parameter is
// initializedized to zero by os.Open(2), indicating no timeout.
func SetTimeout(fd int, tv *syscall.Timeval) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSRTIMEOUT, uintptr(unsafe.Pointer(tv)))
	if err != 0 {
		return syscall.Errno(err)
	}
	return nil
}

// Returns a BpfStat structure of packet statistics.  BpfStat.Recv is the
// number of packets received by the bpf file descriptor since opened or reset
// (including any buffered since the last read call).  BpfStat.Drop is the
// number of packets which were accepted by the filter but dropped by the kernel
// because of buffer overflows (i.e., the application's reads aren't keeping up)
// with the packet traffic
func GetStats(fd int) (*syscall.BpfStat, error) {
	var s syscall.BpfStat
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCGSTATS, uintptr(unsafe.Pointer(&s)))
	if err != 0 {
		return nil, syscall.Errno(err)
	}
	return &s, nil
}

// Enables or disables 'immediate mode', based on the truth value of the
// argument.  When immediate mode is enabled, reads return immediately upon
// packet reception.  Otherwise, a read will block until either the kernel
// buffer becomes full or a timeout occurs.  This is useful for programs like
// rarpd(8) which must respond to messages in real time.  The default for a new
// file is off.
func SetImmediate(fd, m int) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCIMMEDIATE, uintptr(unsafe.Pointer(&m)))
	if err != 0 {
		return syscall.Errno(err)
	}
	return nil
}

// Sets the filter program used by the kernel to discard uninteresting packets.
// An array of instructions and its length is passed in using the BpfInsn
// structure. The filter program is pointed to by the bf_insns field while its
// length in units of `struct bpf_insn' is given by the bf_len field.  Also,
// the actions of BIOCFLUSH are performed.  The only difference between BIOCSETF
// and BIOCSETFNR is BIOCSETF performs the actions of BIOCFLUSH while BIOCSETFNR
// does not.
func SetBpf(fd int, i []syscall.BpfInsn) error {
	var p syscall.BpfProgram
	p.Len = uint32(len(i))
	p.Insns = (*syscall.BpfInsn)(unsafe.Pointer(&i[0]))
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSETF, uintptr(unsafe.Pointer(&p)))
	if err != 0 {
		return syscall.Errno(err)
	}
	return nil
}

// Returns the major and minor version numbers of the filter language currently
// recognized by the kernel.  Before installing a filter, applications must
// check that the current version is compatible with the running kernel.
// Version numbers are compatible if the major numbers match and the application
// minor is less than or equal to the kernel minor.
func GetVersion(fd int) (*syscall.BpfVersion, error) {
	var v syscall.BpfVersion
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCVERSION, uintptr(unsafe.Pointer(&v)))
	if err != 0 {
		return nil, syscall.Errno(err)
	}
	if v.Major != syscall.BPF_MAJOR_VERSION || v.Minor != syscall.BPF_MINOR_VERSION {
		return nil, syscall.EINVAL
	}
	return &v, nil
}

// Gets the status of the 'header complete' flag.  Set to zero if the link level
// source address should be filled in automatically by the interface output
// routine.  Set to one if the link level source address will be written, as
// provided, to the wire.  This flag is initialized to zero by default.
func GetHeaderComplete(fd int) (int, error) {
	var f int
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCGHDRCMPLT, uintptr(unsafe.Pointer(&f)))
	if err != 0 {
		return 0, syscall.Errno(err)
	}
	return f, nil
}

// Sets the status of the 'header complete' flag.  Set to zero if the link level
// source address should be filled in automatically by the interface output
// routine.  Set to one if the link level source address will be written, as
// provided, to the wire.  This flag is initialized to zero by default.
func SetHeaderComplete(fd, f int) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSHDRCMPLT, uintptr(unsafe.Pointer(&f)))
	if err != 0 {
		return syscall.Errno(err)
	}
	return nil
}

// Gets the flag determining whether locally generated packets on the interface
// should be returned by BPF.  Set to zero to see only incoming packets on the
// interface.  Set to one to see packets originating locally and remotely on the
// interface.  This flag is initialized to one by default.
func SeeSent(fd int) (int, error) {
	var f int
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCGSEESENT, uintptr(unsafe.Pointer(&f)))
	if err != 0 {
		return 0, syscall.Errno(err)
	}
	return f, nil
}

// Sets the flag determining whether locally generated packets on the interface
// should be returned by BPF.  Set to zero to see only incoming packets on the
// interface.  Set to one to see packets originating locally and remotely on the
// interface.  This flag is initialized to one by default.
func SetSeeSent(fd, f int) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSSEESENT, uintptr(unsafe.Pointer(&f)))
	if err != 0 {
		return syscall.Errno(err)
	}
	return nil
}

func OpenBpf() (*os.File, error) {
	files, err := ioutil.ReadDir("/dev")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		if strings.Contains(file.Name(), "bpf") {
			fd, err := os.OpenFile(fmt.Sprintf("/dev/%s", file.Name()), os.O_RDWR, 0666)
			if err == nil {
				return fd, nil
			}
		}
	}
	return nil, syscall.ENOENT
}

func (b *Bpf) SetOption(options ...func(b *Bpf) error) error {
	for _, opt := range options {
		if err := opt(b); err != nil {
			return err
		}
	}
	return nil
}

func OpenInterface(dev string, options func(*Bpf) error) (*Bpf, error) {
	fd, err := OpenBpf()
	if err != nil {
		return nil, err
	}

}
