package proto
import "io"
import "golang.org/x/net/ipv6"

func FindHeader( header * ipv6.Header , packet [ ]byte , protos uint8 )( [ ]byte , error ) {
	packet = packet[ 40 : ][ : header.PayloadLen ]
	if header.NextHeader == int( protos ) {
		return packet , nil
	}
	for len( packet ) > 2 {
		var header uint8
		header = packet[ 0 ]
		var length int
		length = int( packet[ 1 ] * 8 ) + 8
		if length > len( packet ) {
			return nil , io.ErrUnexpectedEOF
		}
		packet = packet[ length : ]
		if header == protos {
			return packet , nil
		}
	}
	return nil , io.ErrUnexpectedEOF
}

// IPv6 fixed header
type IPv6Header struct{
	ipv6.Header
}

func ( self * IPv6Header )Pack( option [ ]byte , buffer [ ]byte )[ ]byte {
	return append( append( append( append( append( [ ]byte( nil ) ,
		0x60 + uint8( self.TrafficClass >> 4 ) ,
		uint8( self.TrafficClass << 4 ) + uint8( self.FlowLabel >> 16 ) ,
		uint8( self.FlowLabel >> 8 ) ,
		uint8( self.FlowLabel ) ,
		uint8( ( len( option ) + len( buffer ) ) >> 8 ) ,
		uint8( ( len( option ) + len( buffer ) ) ) ,
		uint8( self.NextHeader ) ,
		uint8( self.HopLimit ) ,
	) , self.Src[ : ] ... ) , self.Dst[ : ] ... ) , option ... ) , buffer ... )
}
