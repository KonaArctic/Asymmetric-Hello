package proto
import "encoding/binary"
import "golang.org/x/net/ipv4"
import "golang.org/x/net/ipv6"

type UDPHeader struct{
	SrcPort uint16
	DestPort uint16
	Length uint16
	Checksum uint16
}

func ( self * UDPHeader)PackIPv4( header * IPv4Header , buffer [ ]byte )[ ]byte {
	var err error
	var packet [ ]byte
	packet , err = binary.Append( nil , binary.BigEndian , UDPHeader{
		SrcPort : self.SrcPort ,
		DestPort : self.DestPort ,
		Length : uint16( 8 + len( buffer ) ) ,
	} )
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
			Protocol : 17 ,
			Src : header.Src ,
			Dst : header.Dst ,
			Options : header.Options ,
		} ,
	} ).Pack( append( packet , buffer ... ) )
}

func ( self * UDPHeader)PackIPv6( header * IPv6Header , buffer [ ]byte )[ ]byte {
	var err error
	var pseudo [ ]byte
	pseudo , err = binary.Append( nil , binary.BigEndian , struct{
		Source [ 16 ]byte
		Destination [ 16 ]byte
		Length uint32
		Zeros [ 3 ]byte
		NextHeader uint8
		UDPHeader
	}{
		Source : [ 16 ]byte( header.Src ) ,
		Destination : [ 16 ]byte( header.Dst ) ,
		Length : 8 + uint32( len( buffer ) ) ,
		NextHeader : 17 ,
		UDPHeader : UDPHeader{
			SrcPort : self.SrcPort ,
			DestPort : self.DestPort ,
			Length : 8 + uint16( len( buffer ) ) ,
		} ,
	} )
	if err != nil {
		return nil
	}
	var packet [ ]byte
	packet , err = binary.Append( nil , binary.BigEndian , UDPHeader{
		SrcPort : self.SrcPort ,
		DestPort : self.DestPort ,
		Length : 8 + uint16( len( buffer ) ) ,
		Checksum : Checksum( append( pseudo , buffer ... ) ) ,
	} )
	if err != nil {
		return nil
	}
	return ( & IPv6Header{
		ipv6.Header{
			TrafficClass : header.TrafficClass ,
			FlowLabel : header.FlowLabel ,
			NextHeader : 17 ,
			HopLimit : header.HopLimit ,
			Src : header.Src ,
			Dst : header.Dst ,
		} ,
	} ).Pack( [ ]byte{ } , append( packet , buffer ... ) )
}
