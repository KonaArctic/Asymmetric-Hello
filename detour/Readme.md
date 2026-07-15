# Detour
Detour is and cross-platform Go library to capture, drop, and inject arbitrary Internet Protocol packets.

## Example
This example captures packets and decide what to do with them.

```
detour , err := detour.New( [ ]detour.Filter{
    detour.Filter{
        // Capture UDP ..
        Protocol : 17 ,
        // ... from ...
        Source : netip.MustParsePrefix( "1:2::/64" ) ,
        SrcPort : 34 ,
        // ... to
        Destination : netip.MustParsePrefix( "5:6::/32" )
        DestPort : 78 ,
    }
} )
if err != nil {
    panic( err )
}
defer detour.Close( )
for {
    buffer := make( [ ]byte , 65535 )
    // Read next captured packet
    length , err := detour.Read( buffer )
    if err != nil {
        panic( err )
    }
    switch whatToDoWithPacket( buffer[ : length ] ) {
        case 0 :
            // Drop this packet
            detour.Discard( )
        case 1 :
            // Inject an additional packet
            detour.Write( createPacket( ).AsBytesSlice( ) )
        default:
            // Do nothing, 
            // packet will continue to destination as normal
    }
}
```

## Requirements

### Linux
You will need [libnftables](https://netfilter.org/projects/nftables/index.html)
and [libnetfilter_qeueue](https://netfilter.org/projects/libnetfilter_queue) 
development libraries and [cgo](https://pkg.go.dev/cmd/cgo). 
On Debian and derivatives install `libnftables-dev` and `libnetfilter-queue-dev`.

### Windows
You will need [WinDivert](https://reqrypt.org/windivert.html). 
Windows support is currently broken.

### BSD
TODO: Implement

## Caveats
Known bugs and problems:

-	Slow and buggy

