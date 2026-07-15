package detour
//#cgo LDFLAGS: -lnftables
//#include <nftables/libnftables.h>
import "C"
import "errors"
import "fmt"
import "unsafe"

func nftablesCreate( filter [ ]Filter , number uint16 , random [ ]byte )error {
	var ok bool
	var status C.int
	var nftctx * C.struct_nft_ctx
	nftctx = C.nft_ctx_new( C.NFT_CTX_DEFAULT )
	if nftctx == nil {
		return errors.New( "nft_ctx_new failed" )
	}
	defer C.nft_ctx_free( nftctx )
	status = C.nft_run_cmd_from_buffer( nftctx , ( * C.char )( unsafe.Pointer( & [ ]byte( fmt.Sprintf( "add table inet kona_detour_%x\x00" , random ) )[ 0 ] ) ) )
	if status != 0 {
		return errors.New( fmt.Sprintf( "%v" , status ) )
	}
	status = C.nft_run_cmd_from_buffer( nftctx , ( * C.char )( unsafe.Pointer( & [ ]byte( fmt.Sprintf( "add chain inet kona_detour_%x in { type filter hook input priority -127 ; policy accept ; comment \"https://github.com/KonaArctic/Asymmetric-Hello/detour\" ; }\x00" , random ) )[ 0 ] ) ) )
	if status != 0 {
		return errors.New( fmt.Sprintf( "%v" , status ) )
	}
	status = C.nft_run_cmd_from_buffer( nftctx , ( * C.char )( unsafe.Pointer( & [ ]byte( fmt.Sprintf( "add chain inet kona_detour_%x out { type filter hook output priority -127 ; policy accept ; comment \"https://github.com/KonaArctic/Asymmetric-Hello/detour\" ; }\x00" , random ) )[ 0 ] ) ) )
	if status != 0 {
		return errors.New( fmt.Sprintf( "%v" , status ) )
	}
	for ; len( filter ) > 0 ; filter = filter[ 1 : ] {
		var nfrule string
		if filter[ 0 ].Source.IsValid( ) {
			nfrule = fmt.Sprintf( "%v %v saddr %v" , nfrule , map[ bool ]string{
				true : "ip" ,
				false : "ip6" ,
			}[ filter[ 0 ].Source.Addr( ).Is4( ) ] , filter[ 0 ].Source )
		}
		if filter[ 0 ].Destination.IsValid( ) {
			nfrule = fmt.Sprintf( "%v %v daddr %v" , nfrule , map[ bool ]string{
				true : "ip" ,
				false : "ip6" ,
			}[ filter[ 0 ].Destination.Addr( ).Is4( ) ] , filter[ 0 ].Destination )
		}
		var protos string
		protos , ok = map[ uint8 ]string{
			6 : "tcp" ,
			17 : "udp" ,
			33 : "dccp" ,
			132 : "sctp" ,
			136 : "udplite" ,
		}[ filter[ 0 ].Protocol ]
		if ok {
			if filter[ 0 ].SrcPort > 0 {
				nfrule = fmt.Sprintf( "%v %v sport %v" , nfrule , protos , filter[ 0 ].SrcPort )
			}
			if filter[ 0 ].DestPort > 0 {
				nfrule = fmt.Sprintf( "%v %v dport %v" , nfrule , protos , filter[ 0 ].DestPort )
			}
		}
		var status C.int
		status = C.nft_run_cmd_from_buffer( nftctx , ( * C.char )( unsafe.Pointer( & [ ]byte( fmt.Sprintf( "insert rule inet kona_detour_%x %v meta l4proto %v %v mark != %v queue num %v bypass\x00" , random , map[ bool ]string{
			true : "in" ,
			false : "out" ,
		}[ filter[ 0 ].Ingress ] , filter[ 0 ].Protocol , nfrule , number , number ) )[ 0 ] ) ) )
		if status != 0 {
			return errors.New( fmt.Sprintf( "%v" , status ) )
		}
	}
	return nil
}


func nftablesDestroy( random [ ]byte )error {
	var nftctx * C.struct_nft_ctx
	nftctx = C.nft_ctx_new( C.NFT_CTX_DEFAULT )
	if nftctx == nil {
		return errors.New( "nft_ctx_new failed" )
	}
	defer C.nft_ctx_free( nftctx )
	var status C.int
	status = C.nft_run_cmd_from_buffer( nftctx , ( * C.char )( unsafe.Pointer( & [ ]byte( fmt.Sprintf( "delete table inet kona_detour_%x\x00" , random ) )[ 0 ] ) ) )
	if status != 0 {
		return errors.New( fmt.Sprintf( "%v" , status ) )
	}
	return nil
}

