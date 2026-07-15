package detour
import "context"
import "crypto/tls"
import "fmt"
import "golang.org/x/net/ipv6"
import "io"
import "net"
import "net/netip"
import "testing"
import "time"

func TestCapture( tester * testing.T ) {
	var err error
	var resolv [ ]netip.Addr
	resolv , err = ( & net.Resolver{
		PreferGo : true ,
		StrictErrors : true ,
	} ).LookupNetIP( context.Background( ) , "ip6" , "example.com" )
	if err != nil {
		tester.Fatal( err )
		return
	}
	var filter [ ]Filter = [ ]Filter{
		Filter{
			Protocol : 254 ,
			Source : netip.PrefixFrom( netip.IPv6Loopback( ) , 128 ) ,
			Destination : netip.PrefixFrom( netip.IPv6Loopback( ) , 128 ) ,
		} ,
	}
	for ; len( resolv ) > 0 ; resolv = resolv[ 1 : ] {
		filter = append( filter , Filter{
			Protocol : 6 ,
			Destination : netip.PrefixFrom( resolv[ 0 ] , 128 ) ,
			DestPort : 443 ,
		} )
	}
	var detour Detour
	detour , err = New( filter )
	if err != nil {
		tester.Fatal( err )
		return
	}
	//defer detour.Close( )
	// Basic test
	var offset chan int = make( chan int , 1 )
	go func( ){
		var err error
		for {
			var buffer [ ]byte = make( [ ]byte , 0 , 65536 )
			var length int
			length , err = detour.Read( buffer[ : cap( buffer ) ] )
			buffer = buffer[ : length ]
			if err != nil {
				tester.Fatal( err )
				return
			}
			offset <- length + <- offset
			var header * ipv6.Header
			header , err = ipv6.ParseHeader( buffer )
			if err != nil {
				tester.Fatal( err )
				return
			}
			_ , _ = fmt.Printf( "%v %v %v %v\r\n" , header.NextHeader , header.Src , header.Dst , len( buffer ) )
		}
	}( )
	println( "doing basic test" )
	for offset <- 0 ; ; offset <- 0 {
		var stream io.ReadWriteCloser
		stream , err = tls.Dial( "tcp6" , "example.com:443" , nil )
		if err != nil {
			tester.Fatal( err )
			return
		}
		err = stream.Close( )
		if err != nil {
			tester.Fatal( err )
			return
		}
		if <- offset >= 50 {
			break
		}
		time.Sleep( time.Second )
	}
	// Check injection allows spoofing
	var listen net.PacketConn
	listen , err = net.ListenPacket( "ip6:254" , "::1" )
	if err != nil {
		tester.Fatal( err )
		return
	}
	println( "injecting packet" )
	_ , err = detour.Write( [ ]byte{
		0x60 , 0x00 , 0x00 , 0x00 ,
		0x00 , 0x01 , 0xFE , 0xFF ,
		0x20 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 ,
		0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x01 ,
		0xFF ,
	} )
	if err != nil {
		tester.Fatal( err )
		return
	}
	err = listen.SetReadDeadline( time.Now( ).Add( time.Second * 10 ) )
	if err != nil {
		tester.Fatal( err )
		return
	}
	println( "checking injection spoofing" )
	var remote net.Addr
	_ , remote , err = listen.ReadFrom( make( [ ]byte , 65535 , 65535 ) )
	if err != nil {
		tester.Fatal( err )
		return
	}
	if remote.String( ) != "2000::" {
		tester.Fatal( remote )
		return
	}
	// Check Discard works
	_ , err = listen.WriteTo( [ ]byte{
		0xF7 ,
	} , & net.IPAddr{
		IP : net.ParseIP( "::1" ) ,
	} )
	if err != nil {
		tester.Fatal( err )
		return
	}
	for {
		println( "waiting for packet to discard" )
		var buffer [ ]byte = make( [ ]byte , 0 , 65536 )
		var length int
		length , err = detour.Read( buffer[ : cap( buffer ) ] )
		buffer = buffer[ : length ]
		if err != nil {
			tester.Fatal( err )
			return
		}
		var header * ipv6.Header
		header , err = ipv6.ParseHeader( buffer )
		if err != nil {
			tester.Fatal( err )
			return
		}
		if header.NextHeader == 254 {
			err = detour.Discard( )
			if err != nil {
				tester.Fatal( err )
				return
			}
			break
		}
	}
	println( "looking for discarded packet" )
	_ , _ , err = listen.ReadFrom( make( [ ]byte , 65535 , 65535 ) )
	if err == nil {
		tester.Fatal( err )
		return
	}
	// Test IPv4
	println( "testing ipv4" )
	var ip4det Detour
	ip4det , err = New( [ ]Filter{
		Filter {
			Protocol : 17 ,
			Destination : netip.MustParsePrefix( "127.0.0.0/32" ) ,
			Source : netip.MustParsePrefix( "0.1.2.3/32" ) ,
			DestPort : 53 ,
		} ,
	} )
	if err != nil {
		tester.Fatal( err )
		return
	}
	_ , err = detour.Write( [ ]byte{
		0x45 , 0x00 , 0x00 , 0x1D ,
		0x0D , 0x08 , 0x40 , 0x00 ,
		0x40 , 0x11 , 0xAC , 0xC4 ,
		0x00 , 0x01 , 0x02 , 0x03 ,
		0x7F , 0x00 , 0x00 , 0x00 ,
		0xB5 , 0xFC , 0x00 , 0x35 ,
		0x00 , 0x09 , 0x81 , 0x1E ,
		0x00 ,
	} )
	if err != nil {
		tester.Fatal( err )
		return
	}
	_ , err = ip4det.Read( make( [ ]byte , 65535 , 65535 ) )
	if err != nil {
		tester.Fatal( err )
		return
	}
	// Confirm injected packets are not captured
	println( "injecting packet" )
	_ , err = detour.Write( [ ]byte{
		0x60 , 0x00 , 0x00 , 0x00 ,
		0x00 , 0x01 , 0xFE , 0xFF ,
		0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x01 ,
		0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x01 ,
		0xF0 ,
	} )
	if err != nil {
		tester.Fatal( err )
		return
	}
	go func( ){
		var err error
		for {
			println( "trying to capture injected packet" )
			var buffer [ ]byte = make( [ ]byte , 0 , 65536 )
			var length int
			length , err = detour.Read( buffer[ : cap( buffer ) ] )
			buffer = buffer[ : length ]
			if err != nil {
				tester.Fatal( err )
				return
			}
			var header * ipv6.Header
			header , err = ipv6.ParseHeader( buffer )
			if err != nil {
				tester.Fatal( err )
				return
			}
			if  header.NextHeader == 254 &&
			    buffer[ len( buffer ) - 1 ] == 0xF0 {
				tester.Fatal( "caught an injected packet" )
				return
			}
		}
	}( )
	time.Sleep( time.Second )
	println( "success" )
	err = detour.Close( )
	if err != nil {
		tester.Fatal( err )
		return
	}
}

// sudo nft list ruleset | grep --extended-regexp --only-matching kona_detour_\(in\|out\)_\[0-9a-fA-F\]+ | sort | uniq | sudo xargs --max-arg=1 -- nft flush chain ip6 filter
