package client
import "context"
import "crypto/rand"
import "encoding/base64"
import "encoding/binary"
import "errors"
import "fmt"
import "github.com/KonaArctic/Asymmetric-Hello/detour"
import "github.com/KonaArctic/Asymmetric-Hello/proto"
import "golang.org/x/net/ipv6"
import "io"
import "net"
import "net/http"
import "net/netip"
import "net/url"
import "os"
import "slices"

type Client struct{
	Always map[ netip.Prefix ]any
	Locate * url.URL
	Resolv string
}

func ( self * Client )Run( )error {
	var err error
	var finish * waitFirst = & waitFirst{ }
	var listen net.PacketConn
	listen , err = self.resolver( finish )
	if err != nil {
		return err
	}
	defer listen.Close( )
	var closer io.Closer
	closer , err = self.startDNS( finish , listen )
	if err != nil {
		return err
	}
	defer closer.Close( )
	closer , err = self.startAH( finish )
	if err != nil {
		return err
	}
	defer closer.Close( )
	return finish.Wait( )
}

// Run Asymmetric Hello
func ( self * Client )startAH( finish * waitFirst )( io.Closer , error ) {
	var err error
	var ipaddr [ ]netip.Addr
	ipaddr , err = ( & net.Resolver{
		PreferGo : true ,
		StrictErrors : true ,
	} ).LookupNetIP( context.Background( ) , "ip6" , self.Locate.Hostname( ) )
	if err != nil {
		return nil , err
	}
	var socket detour.Detour
	socket , err = detour.New( [ ]detour.Filter{
		detour.Filter{
			Protocol : 6 ,
			DestPort : 443 ,
		} ,
	} )
	if err != nil {
		return nil , err
	}
	go finish.Do( func( )error{
		var err error
		var ok bool
		var stream map[ string ][ ]uint32 = map[ string ][ ]uint32{ }
		var packet [ ]byte = make( [ ]byte , 0 , 65535 )
		for {
			var length int
			length , err = socket.Read( packet[ : cap( packet ) ] )
			if err != nil {
				return err
			}
			packet = packet[ : length ]
			var ip6hdr * ipv6.Header
			ip6hdr , err = ipv6.ParseHeader( packet )
			if err != nil {
				return err
			}
			if slices.Contains( ipaddr , netip.AddrFrom16( [ 16 ]byte( ip6hdr.Dst ) ) ) {
				// Avoid loops
				continue
			}
			var buffer [ ]byte
			buffer , err = proto.FindHeader( ip6hdr , packet , 6 )
			if err != nil {
				return err
			}
			var tcphdr proto.TCPHeader
			_ , err = binary.Decode( buffer , binary.BigEndian , & tcphdr )
			if err != nil {
				return err
			}
			var tuples string
			tuples = fmt.Sprint( ip6hdr.Src , ip6hdr.Dst , tcphdr.SrcPort , tcphdr.DestPort )
			if findPrefix( self.Always , netip.AddrFrom16( [ 16 ]byte( ip6hdr.Dst ) ) ) {
				// For some non-obvious reason some anycast addresses need all packets to be rerouted
				if tcphdr.Flags & 0b00000010 > 0 {
					_ , _ = fmt.Fprintf( os.Stdout , "New anycast stream to %v\r\n" , ip6hdr.Dst )
					stream[ tuples ] = make( [ ]uint32 , 0 , 3 )
				} else {
					var offset [ ]uint32
					offset , ok = stream[ tuples ]
					if ! ok {
						continue
					}
					if tcphdr.Flags & 0b00000101 > 0 {
						// FIN / RST
						delete( stream , tuples )
					} else {
						if int( tcphdr.DataOffset ) >> 4 * 4 < len( buffer ) {
							// Has segment data
							if slices.Contains( offset , tcphdr.Sequence ) {
								// Retransmission of ClientHello
								err = socket.Discard( )
								if err != nil {
									return err
								}
							} else {
								if len( offset ) < 2 {
									// New ClientHello packet
									err = socket.Discard( )
									if err != nil {
										return err
									}
									stream[ tuples ] = append( offset , tcphdr.Sequence )
								}
							}
						}
					}
				}
			} else {
				// Not anycast
				if tcphdr.Flags & 0b00000010 > 0 {
					_ , _ = fmt.Fprintf( os.Stdout , "New TCP stream to %v\r\n" , ip6hdr.Dst )
					stream[ tuples ] = make( [ ]uint32 , 0 , 3 )
					continue
				}
				var offset [ ]uint32
				offset , ok = stream[ tuples ]
				if ! ok {
					continue
				}
				if tcphdr.Flags & 0b00000101 > 0 {
					// FIN / RST
					delete( stream , tuples )
					continue
				}
				if int( tcphdr.DataOffset ) >> 4 * 4 >= len( buffer ) {
					// No segment data, no rerouting needed
					continue
				}
				if slices.Contains( offset , tcphdr.Sequence ) {
					// Retransmission
				} else {
					if len( offset ) >= 2 {
						// That's enough packets
						//delete( stream , tuples )
						continue
					}
					// Another initial packet
					stream[ tuples ] = append( offset , tcphdr.Sequence )
				}
				// Reroute first few packets
				err = socket.Discard( )
				if err != nil {
					return err
				}
			}
			// Recalculate checksum - this is needed because of offloading
			var encode string
			encode = base64.RawURLEncoding.EncodeToString( tcphdr.PackIPv6( & proto.IPv6Header{
				Header : * ip6hdr ,
			} , buffer[ 20 : tcphdr.DataOffset >> 4 * 4 ] , buffer[ tcphdr.DataOffset >> 4 * 4 : ] ) )
			go finish.Do( func( )error{
				var respon * http.Response
				respon , err = http.DefaultClient.Do( & http.Request{
					Method : http.MethodGet ,
					URL : & url.URL{
						Scheme : self.Locate.Scheme ,
						User : self.Locate.User ,
						Host : map[ bool ]string{
							true : self.Locate.Fragment ,
							false : self.Locate.Host ,
						}[ self.Locate.Fragment != "" ] ,
						Path : self.Locate.Path ,
						RawQuery : url.Values( map[ string ][ ]string{
							"b" : [ ]string{	// Cache bust
								rand.Text( ) ,
							} ,
							"c" : [ ]string{
								"i" ,
							} ,
							"d" : [ ]string{
								encode ,
							} ,
						} ).Encode( ) + "&" + self.Locate.RawQuery ,
					} ,
					Host : self.Locate.Host ,
				} )
				if err != nil {
					return err
				}
				err = respon.Body.Close( )
				if err != nil {
					return err
				}
				if respon.StatusCode != http.StatusOK {
					return errors.New( respon.Status )
				}
				return nil
			} )
		}
	} )
	return socket , nil
}
