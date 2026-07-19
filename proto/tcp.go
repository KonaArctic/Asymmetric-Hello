package proto
import "encoding/binary"
import "golang.org/x/net/ipv4"
import "golang.org/x/net/ipv6"

// TCP fixed header
type TCPHeader struct{
	SrcPort uint16
	DestPort uint16
	Sequence uint32
	Acknowledge uint32
	DataOffset uint8
	Flags uint8
	Window uint16
	Checksum uint16
	UrgentPtr uint16
}

func ( self * TCPHeader )PackIPv4( header * IPv4Header , option [ ]byte , buffer [ ]byte )[ ]byte {
	var err error
	var pseudo [ ]byte
	pseudo , err = binary.Append( nil , binary.BigEndian , struct{
		Source [ 4 ]byte
		Destination [ 4 ]byte
		Zeros [ 1 ]byte
		Protocol uint8
		Length uint16
		TCPHeader
	}{
		Source : [ 4 ]byte( header.Src ) ,
		Destination : [ 4 ]byte( header.Dst ) ,
		Protocol : 6 ,
		Length : uint16( 20 + len( option ) + len( buffer ) ) ,
		TCPHeader : TCPHeader{
			SrcPort : self.SrcPort ,
			DestPort : self.DestPort ,
			Sequence : self.Sequence ,
			Acknowledge : self.Acknowledge ,
			DataOffset : uint8( ( ( 20 + len( option ) ) / 4 ) << 4 ) ,
			Flags : self.Flags ,
			Window : self.Window ,
			UrgentPtr : self.UrgentPtr ,
		} ,
	} )
	if err != nil {
		return nil
	}
	var packet [ ]byte
	packet , err = binary.Append( nil , binary.BigEndian , TCPHeader{
		SrcPort : self.SrcPort ,
		DestPort : self.DestPort ,
		Sequence : self.Sequence ,
		Acknowledge : self.Acknowledge ,
		DataOffset : uint8( ( ( 20 + len( option ) ) / 4 ) << 4 ) ,
		Flags : self.Flags ,
		Window : self.Window ,
		Checksum : Checksum( append( append( append( pseudo , option ... ) , buffer ... ) , make( [ ]byte , len( buffer ) % 2 , 1 ) ... ) ) ,
		UrgentPtr : self.UrgentPtr ,
	}  )
	if err != nil {
		return nil
	}
	return ( & IPv4Header{
		ipv4.Header{ 
			TOS : header.TOS ,
			ID : header.ID ,
			Flags : header.Flags ,
			FragOff : header.FragOff ,
			TTL : header.TTL ,
			Protocol : 6 ,
			Src : header.Src ,
			Dst : header.Dst ,
			Options : header.Options ,
		} ,
	} ).Pack( append( append( packet , option ... ) , buffer ... ) )
}

func ( self * TCPHeader )PackIPv6( header * IPv6Header , option [ ]byte , buffer [ ]byte )[ ]byte {
	var err error
	var pseudo [ ]byte
	pseudo , err = binary.Append( nil , binary.BigEndian , struct{
		Source [ 16 ]byte
		Destination [ 16 ]byte
		Length uint32
		Zeros [ 3 ]byte
		Protocol uint8
		TCPHeader
	}{
		Source : [ 16 ]byte( header.Src ) ,
		Destination : [ 16 ]byte( header.Dst ) ,
		Length : uint32( 20 + len( option ) + len( buffer ) ) ,
		Protocol : 6 ,
		TCPHeader : TCPHeader{
			SrcPort : self.SrcPort ,
			DestPort : self.DestPort ,
			Sequence : self.Sequence ,
			Acknowledge : self.Acknowledge ,
			DataOffset : uint8( ( ( 20 + len( option ) ) / 4 ) << 4 ) ,
			Flags : self.Flags ,
			Window : self.Window ,
			UrgentPtr : self.UrgentPtr ,
		} ,
	} )
	if err != nil {
		return nil
	}
	var packet [ ]byte
	packet , err = binary.Append( nil , binary.BigEndian , TCPHeader{
		SrcPort : self.SrcPort ,
		DestPort : self.DestPort ,
		Sequence : self.Sequence ,
		Acknowledge : self.Acknowledge ,
		DataOffset : uint8( ( ( 20 + len( option ) ) / 4 ) << 4 ) ,
		Flags : self.Flags ,
		Window : self.Window ,
		Checksum : Checksum( append( append( append( pseudo , option ... ) , buffer ... ) , make( [ ]byte , len( buffer ) % 2 , 1 ) ... ) ) ,
		UrgentPtr : self.UrgentPtr ,
	}  )
	if err != nil {
		return nil
	}
	return ( & IPv6Header{
		ipv6.Header{
			TrafficClass : header.TrafficClass ,
			FlowLabel : header.FlowLabel ,
			NextHeader : 6 ,
			HopLimit : header.HopLimit ,
			Src : header.Src ,
			Dst : header.Dst ,
		} ,
	} ).Pack( [ ]byte{ } , append( append( packet , option ... ) , buffer ... ) )
}
