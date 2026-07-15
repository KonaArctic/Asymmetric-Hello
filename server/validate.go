package server
import "encoding/binary"
import "github.com/KonaArctic/Asymmetric-Hello/proto"
import "golang.org/x/net/ipv6"

func validpacket( hostnm string , packet [ ]byte )bool {
	var err error
	if len( packet ) > 1500 {
		// Bigger than MTU
		return false
	}
	var ip6hdr * ipv6.Header
	ip6hdr , err = ipv6.ParseHeader( packet )
	if err != nil {
		return false
	}
	if ip6hdr.Src.String( ) != hostnm {
		return false
	}
	if ip6hdr.NextHeader != 6 {
		// Not TCP / extension headers not allowed
		return false
	}
	if ip6hdr.PayloadLen + 40 != len( packet ) {
		// Lengths differ / extra data not allowed
		return false
	}
	var tcphdr proto.TCPHeader
	_ , err = binary.Decode( packet[ 40 : ] , binary.BigEndian , & tcphdr )
	if err != nil {
		return false
	}
	if tcphdr.DestPort != 443 {
		// Not HTTPS
		return false
	}
	// TODO Validate TCP header, options, TLS ClientHello
	return true
}
