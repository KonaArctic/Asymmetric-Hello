// Cross-platform Internet Protocol raw packet capture and injection
package detour
import "errors"
import "io"
import "net/netip"

// Capture and inject packets.
type Detour interface{
	// Readers must provide a 64KiB buffer.
	// Writers must provide a valid packet.
	io.ReadWriteCloser
	// Drop last read packet.
	Discard( )error
}

// Filter to only capture matching packets.
type Filter struct{
	// Set to true to capture ingress packets instead of egress.
	Ingress bool
	// Transport layer protocol number.
	Protocol uint8
	// Source and destination addresses.
	Source netip.Prefix
	Destination netip.Prefix
	// Source and destination port numbers.
	// Only valid for TCP, UDP, DCCP, or SCTP.
	SrcPort uint16
	DestPort uint16
}

// Enable packet capture and injection on this machine with filter.
// Its the caller's responsibility to not call Close twice or before or during Read.
func New( filter [ ]Filter )( Detour , error ) {
	return create( filter )
}

// You tried to write a packet bigger than MTU
var ErrPacketTooBig error = errors.New( "packet too big" )
