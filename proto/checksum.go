package proto
import "encoding/binary"

// Compute Internet checksum
// https://en.wikipedia.org/wiki/Internet_Checksum
func Checksum( buffer [ ]byte )uint16 {
	var totals uint32
	for ; len( buffer ) > 1 ; buffer = buffer[ 2 : ] {
		totals += uint32( binary.BigEndian.Uint16( buffer ) )
	}
	if len( buffer ) > 0 {
		totals += uint32( buffer[ 0 ] )
	}
	totals = ( totals & 0xFFFF ) + ( totals >> 16 )
	totals = ( totals & 0xFFFF ) + ( totals >> 16 )
	return uint16( ^ totals )
}
