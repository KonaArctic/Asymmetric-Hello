package client
import "bytes"
import "crypto/rand"
import "encoding/base64"
import "encoding/binary"
import "errors"
import "fmt"
import "github.com/KonaArctic/Asymmetric-Hello/detour"
import "github.com/KonaArctic/Asymmetric-Hello/proto"
import "golang.org/x/net/dns/dnsmessage"
import "golang.org/x/net/ipv4"
import "io"
import "net"
import "net/http"
import "net/netip"
import "net/url"
import "os"
import "os/exec"
import "strings"
import "sync"

// Forward DNS queries to remote server.
func ( self * Client )resolver( finish * waitFirst )( net.PacketConn , error ) {
	var err error
	var listen net.PacketConn
	listen , err = net.ListenPacket( "udp6" , "[::1]:0" )
	if err != nil {
		return nil , err
	}
	go finish.Do( func( )error{
		var err error
		var buffer [ ]byte = make( [ ]byte , 0 , 65535 )
		for {
			var length int
			var remote net.Addr
			length , remote , err = listen.ReadFrom( buffer[ : cap( buffer ) ] )
			buffer = buffer[ : length ]
			if err != nil {
				return err
			}
			var encode string
			encode = base64.RawURLEncoding.EncodeToString( buffer )
			go finish.Do( func( )error{
				var err error
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
								"r" ,
							} ,
							"d" : [ ]string{
								encode ,
							} ,
						} ).Encode( ) + "&" + self.Locate.RawQuery ,
					} ,
					Host : self.Locate.Host ,
				} )
				if err != nil {
					println( err.Error( ) )
					return err
				}
				defer respon.Body.Close( )
				if respon.StatusCode != http.StatusOK {
					return errors.New( respon.Status )
				}
				var buffer [ ]byte
				buffer , err = io.ReadAll( & io.LimitedReader{
					R : respon.Body ,
					N : 65535 ,
				} )
				if err != nil {
					return err
				}
				err = respon.Body.Close( )
				if err != nil {
					return err
				}
				_ , _ = listen.WriteTo( buffer , remote )
				return nil
			} )
		}
	} )
	return listen , nil
}

// Capture and resolve DNS queries using script
func ( self * Client )startDNS( finish * waitFirst , listen net.PacketConn )( io.Closer , error ) {
	var err error
	var random [ ]byte = make( [ ]byte , 16 , 16 )
	_ , err = io.ReadFull( rand.Reader , random )
	if err != nil {
		return nil , err
	}
	// Capture DNS packets
	var socket detour.Detour
	socket , err = detour.New( [ ]detour.Filter{
		detour.Filter{
			Protocol : 17 ,
			DestPort : 53 ,
		} ,
	} )
	if err != nil {
		return nil , err
	}
	go finish.Do( func( )error{
		var err error
		var caches map[ dnsmessage.Question ]func( )( [ ]dnsmessage.Resource , error ) = map[ dnsmessage.Question ]func( )( [ ]dnsmessage.Resource , error ){ }
		var locker chan any = make( chan any , 1 )
		var packet [ ]byte = make( [ ]byte , 0 , 65535 )
		for {
			var length int
			length , err = socket.Read( packet[ : cap( packet ) ] )
			packet = packet[ : length ]
			if err != nil {
				return err
			}
			// TODO IPv6
			if packet[ 0 ] >> 4 != 4 {
				err = socket.Discard( )
				if err != nil {
					return err
				}
				continue
			}
			// Decode network stack
			var ip4hdr * ipv4.Header
			ip4hdr , err = ipv4.ParseHeader( packet )
			if err != nil {
				return err
			}
			var udphdr proto.UDPHeader
			_ , err = binary.Decode( packet[ ip4hdr.Len : ] , binary.BigEndian , & udphdr )
			if err != nil {
				return err
			}
			var querys * dnsmessage.Message = & dnsmessage.Message{ }
			err = querys.Unpack( packet[  ip4hdr.Len + 8 : ] )
			if err != nil {
				continue
			}
			if len( querys.Questions ) == 0 {
				continue
			}
			// Avoid loops
			if bytes.Contains( packet , random ) {
				continue
			}
			if querys.Questions[ 0 ].Name.String( ) == self.Locate.Hostname( ) + "." {
				continue
			}
			// Process query
			err = socket.Discard( )
			if err != nil {
				return err
			}
			go finish.Do( func( )error{
				var err error
				var ok bool
				var answer [ ]dnsmessage.Resource
				var values dnsmessage.Question
				for _ , values = range querys.Questions {
					if values.Type != dnsmessage.TypeAAAA {
						continue
					}
					if strings.Trim( values.Name.String( ) , "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-" ) != "" {	// Use punycode
						continue
					}
					var callee func( )( [ ]dnsmessage.Resource , error )
					locker <- true
					callee , ok = caches[ values ]
					// Record is in cache or already processing
					if ! ok {
						callee = sync.OnceValues( func( )( [ ]dnsmessage.Resource , error ){
							var err error
							var buffer * strings.Builder = & strings.Builder{ }
							err = ( & exec.Cmd{
								Path : "/bin/bash" ,
								Args : [ ]string{
									"bash" ,
									self.Resolv ,
									listen.LocalAddr( ).String( ) ,
									fmt.Sprintf( "%X" , random ) ,
									values.Name.String( ) ,
								} ,
								Stdout : buffer ,
								Stderr : os.Stderr ,
							} ).Run( )
							if err != nil {
								return nil , err
							}
							var record [ ]dnsmessage.Resource
							var fields string
							for _ , fields = range strings.Fields( buffer.String( ) ) {
								var ipaddr netip.Addr
								ipaddr , err = netip.ParseAddr( fields )
								if err != nil {
									continue
								}
								record = append( record , dnsmessage.Resource{
									Header : dnsmessage.ResourceHeader{
										Name : values.Name ,
										Class : dnsmessage.ClassINET ,
										TTL : 60 ,
									} ,
									Body : & dnsmessage.AAAAResource{
										AAAA : ipaddr.As16( ) ,
									} ,
								} )
							}
							return record , nil
						} )
						caches[ values ] = callee
					}
					<- locker
					var record [ ]dnsmessage.Resource
					record , err = callee( )
					if err != nil {
						return err
					}
					answer = append( answer , record ... )
				}
				// Encode network stack
				var buffer [ ]byte
				buffer , err = ( & dnsmessage.Message{
					Header : dnsmessage.Header{
						ID : querys.Header.ID ,
						Response : true ,
						RecursionAvailable : true ,
						RCode : dnsmessage.RCodeSuccess ,
					} ,
					Questions : querys.Questions ,
					Answers : answer ,
				} ).Pack( )
				if err != nil {
					return err
				}
				_ , err = socket.Write( ( & proto.UDPHeader{
					DestPort : udphdr.SrcPort ,
					SrcPort : 53 ,
				} ).PackIPv4( & proto.IPv4Header{
					Header : ipv4.Header{
						Dst : ip4hdr.Src ,
						Src : ip4hdr.Dst ,
					} ,
				} , buffer ) )
				if err != nil {
					return err
				}
				return nil
			} )
		}
	} )
	return socket , nil
}
