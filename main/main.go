package main
import "bufio"
import "crypto/tls"
import "encoding/hex"
import "errors"
import "flag"
import "fmt"
import "github.com/KonaArctic/Asymmetric-Hello/client"
import "github.com/KonaArctic/Asymmetric-Hello/server"
import "io"
import "net/http"
import "net/netip"
import "net/url"
import "os"
import "strings"
import "time"

func main( ) {
	os.Exit( func( argues [ ]string , stream io.ReadWriter )int{
		var err error
		if len( argues ) < 1 {
			return 2
		}
		switch argues[ 0 ] {
			case "client" :
				var option flag.FlagSet
				option.SetOutput( io.Discard )
				var always map[ netip.Prefix ]any = map[ netip.Prefix ]any{ }
				option.Func( "anycast" , "anycatch-v6-prefixes.txt" , func( inputs string )error{
					var err error
					var filept io.ReadCloser
					filept , err = os.Open( inputs )
					if err != nil {
						return err
					}
					defer filept.Close( )
					var reader * bufio.Reader
					reader = bufio.NewReader( filept )
					for {
						var buffer [ ]byte
						buffer , _ , err = reader.ReadLine( )
						switch err {
							case nil :
							case io.EOF :
								err = filept.Close( )
								if err != nil {
									return err
								}
								return nil
							default :
								return err
						}
						var prefix netip.Prefix
						prefix , err = netip.ParsePrefix( strings.TrimSpace( string( buffer ) ) )
						if err != nil {
							return err
						}
						always[ prefix.Masked( ) ] = nil
					}
				} )
				var locate * url.URL
				option.Func( "server" , "https://:token@example.com/" , func( inputs string )error{
					locate , err = url.Parse( inputs )
					return err
				} )
				var resolv * string
				resolv = option.String( "resolv" , "resolve/resolve.sh" , "" )
				err = option.Parse( argues[ 1 : ] )
				if err != nil {
					_ , _ = fmt.Fprintf( os.Stderr , "%v\r\n" , err )
					return 2
				}
				err = ( & client.Client{
					Always : always ,
					Locate : locate ,
					Resolv : * resolv ,
				} ).Run( )
				_ , _ = fmt.Fprintf( os.Stderr , "%v\r\n" , err )
				return 1
			case "server" :
				var buffer [ ]byte
				buffer = [ ]byte( os.Getenv( "KONA_TLS_CERTIFICATE_WITH_PRIVATE_KEY" ) )
				var crtkey tls.Certificate
				crtkey , err = tls.X509KeyPair( buffer , buffer )
				if err != nil {
					_ , _ = fmt.Fprintf( os.Stderr , "%v\r\n" , err )
					return 2
				}
				var option flag.FlagSet
				option.SetOutput( io.Discard )
				var delays * time.Duration
				delays = option.Duration( "delays" , time.Second * 10 , "" )
				var header * string
				header = option.String( "header" , "" , "" )
				var listen * string
				listen = option.String( "listen" , "[::]:443" , "" )
				var resolv netip.AddrPort
				option.Func( "resolv" , "" , func( inputs string )error{
					resolv , err = netip.ParseAddrPort( inputs )
					return err
				} )
				var tokens [ ][ 32 ]byte
				option.Func( "tokens" , "" , func( inputs string )error{
					var buffer [ ]byte
					buffer , err = hex.DecodeString( inputs )
					if err != nil {
						return err
					}
					if len( buffer ) != 32 {
						return errors.New( "" )
					}
					tokens = append( tokens , [ 32 ]byte( buffer ) )
					return nil
				} )
				err = option.Parse( argues[ 1 : ] )
				if err != nil {
					_ , _ = fmt.Fprintf( os.Stderr , "%v\r\n" , err )
					return 2
				}
				if len( tokens ) == 0 {
					_ , _ = fmt.Fprintf( os.Stderr , "no tokens given\r\n" )
					return 2
				}
				err = ( & http.Server{
					Addr : * listen ,
					Handler : & server.Server{
						Delays : * delays ,
						Header : * header ,
						Resolv : resolv ,
						Tokens : tokens ,
					} ,
					TLSConfig : & tls.Config{
						Certificates : [ ]tls.Certificate{
							crtkey ,
						} ,
					} ,
				} ).ListenAndServeTLS( "" , "" )
				_ , _ = fmt.Fprintf( os.Stderr , "%v\r\n" , err )
				return 3
			default :
				return 2
		}
	}( os.Args[ 1 : ] , struct{
		io.Reader
		io.Writer
	}{
		Reader : os.Stdin ,
		Writer : os.Stdout ,
	} ) )
}
