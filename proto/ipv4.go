package proto
import "golang.org/x/net/ipv4"

// IPv4 header
type IPv4Header struct{
	ipv4.Header
}

func ( self * IPv4Header )Pack( buffer [ ]byte )[ ]byte {
	var err error
	var pseudo [ ]byte
	pseudo , err = ( & ipv4.Header{
		Version : ipv4.Version ,
		Len : ipv4.HeaderLen + len( self.Options ) ,
		TOS : self.TOS ,
		TotalLen : ipv4.HeaderLen + len( self.Options ) + len( buffer ) ,
		ID : self.ID ,
		Flags : self.Flags ,
		FragOff : self.FragOff ,
		TTL : self.TTL ,
		Protocol : self.Protocol ,
		Src : self.Src ,
		Dst : self.Dst ,
		Options : self.Options ,
	} ).Marshal( )
	if err != nil {
		return nil
	}
	var packet [ ]byte
	packet , err = ( & ipv4.Header{
		Version : ipv4.Version ,
		Len : ipv4.HeaderLen + len( self.Options ) ,
		TOS : self.TOS ,
		TotalLen : ipv4.HeaderLen + len( self.Options ) + len( buffer ) ,
		ID : self.ID ,
		Flags : self.Flags ,
		FragOff : self.FragOff ,
		TTL : self.TTL ,
		Protocol : self.Protocol ,
		Checksum : int( Checksum( pseudo ) ) ,
		Src : self.Src ,
		Dst : self.Dst ,
		Options : self.Options ,
	} ).Marshal( )
	if err != nil {
		return nil
	}
	return append( packet , buffer ... )
}
