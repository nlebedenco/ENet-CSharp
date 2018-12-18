/*
 *  Managed C# wrapper for an extended version of ENet
 *  Copyright (c) 2013 James Bellinger
 *  Copyright (c) 2016 Nate Shoffner
 *  Copyright (c) 2018 Stanislav Denisov
 *  Copyright (c) 2019 Nicolas Lebedenco
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace ENet
{
    [Flags]
    public enum PacketFlags
    {
        None = 0,
        Reliable = 1 << 0,
        Unsequenced = 1 << 1,
        NoAllocate = 1 << 2,
        UnreliableFragment = 1 << 3
    }

    public enum EventType
    {
        None = 0,
        Connect = 1,
        Disconnect = 2,
        Receive = 3,
        Timeout = 4
    }

    public enum PeerState
    {
        Uninitialized = -1,
        Disconnected = 0,
        Connecting = 1,
        AcknowledgingConnect = 2,
        ConnectionPending = 3,
        ConnectionSucceeded = 4,
        Connected = 5,
        DisconnectLater = 6,
        Disconnecting = 7,
        AcknowledgingDisconnect = 8,
        Zombie = 9
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENetAddress
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] host;
        public ushort port;
        public ushort sin6_scope_id;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENetEvent
    {
        public EventType type;
        public IntPtr peer;
        public byte channelId;
        public uint data;
        public IntPtr packet;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENetCallbacks
    {
        public IntPtr malloc;
        public IntPtr free;
        public IntPtr out_of_memory;
    }

    public delegate IntPtr AllocCallback(IntPtr size);
    public delegate void FreeCallback(IntPtr memory);
    public delegate void OutOfMemoryCallback();
    public delegate void PacketFreeCallback(Packet packet);


    internal static class ArrayPool
    {
        [ThreadStatic]
        private static byte[] buffer;

        public static byte[] GetBuffer()
        {
            if (buffer == null)
                buffer = new byte[64];

            return buffer;
        }
    }


    public struct Address
    {
        public Address(ENetAddress address)
        {
            nativeAddress = address;
        }

        internal ENetAddress nativeAddress;

        public string Host
        {
            get
            {
                byte[] hostName = ArrayPool.GetBuffer();

                if (Native.enet_address_get_host(ref nativeAddress, hostName, (IntPtr)hostName.Length) == 0)
                    return Encoding.ASCII.GetString(hostName, 0, hostName.AnsiStrLen());
                else
                    return string.Empty;
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                if (Native.enet_address_set_host(ref nativeAddress, Encoding.ASCII.GetBytes(value)) != 0)
                    throw new ArgumentException("value"); 
            }
        }

        public ushort Port
        {
            get { return nativeAddress.port; }

            set { nativeAddress.port = value; }
        }
    }


    public struct Event
    {
        internal ENetEvent nativeEvent;

        internal Event(ENetEvent nativeEvent)
        {
            this.nativeEvent = nativeEvent;
        }

        public EventType Type
        {
            get { return nativeEvent.type; }
        }

        public Peer Peer
        {
            get { return new Peer(nativeEvent.peer); }
        }

        public byte ChannelId
        {
            get { return nativeEvent.channelId; }
        }

        public uint Data
        {
            get { return nativeEvent.data; }
        }

        public Packet Packet
        {
            get { return new Packet(nativeEvent.packet); }
        }
    }


    public struct Callbacks
    {
        internal ENetCallbacks nativeCallbacks;

        public Callbacks(AllocCallback allocCallback, FreeCallback freeCallback, OutOfMemoryCallback outOfMemoryCallback)
        {
            nativeCallbacks.malloc = Marshal.GetFunctionPointerForDelegate(allocCallback);
            nativeCallbacks.free = Marshal.GetFunctionPointerForDelegate(freeCallback);
            nativeCallbacks.out_of_memory = Marshal.GetFunctionPointerForDelegate(outOfMemoryCallback);
        }
    }


    public struct Packet : IDisposable
    {
        public Packet(IntPtr packet)
        {
            nativePacket = packet;
        }

        internal IntPtr nativePacket;

        public bool IsValid
        {
            get { return nativePacket != IntPtr.Zero; }
        }

        public IntPtr Data
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_packet_get_data(nativePacket);
            }
        }

        public int Length
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_packet_get_length(nativePacket);
            }
        }

        internal void ThrowIfNotValid()
        {
            if (!IsValid)
                throw new InvalidOperationException("Packet not created");
        }

        public void SetFreeCallback(PacketFreeCallback callback)
        {
            ThrowIfNotValid();
            Native.enet_packet_set_free_callback(nativePacket, Marshal.GetFunctionPointerForDelegate(callback));
        }

        public void Create(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            Create(data, data.Length);
        }

        public void Create(byte[] data, int length)
        {
            Create(data, length, PacketFlags.None);
        }

        public void Create(byte[] data, PacketFlags flags)
        {
            Create(data, data.Length, flags);
        }

        public void Create(byte[] data, int length, PacketFlags flags)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (length < 0 || length > data.Length)
                throw new ArgumentOutOfRangeException();

            nativePacket = Native.enet_packet_create(data, (IntPtr)length, flags);
        }

        public void Create(IntPtr data, int length, PacketFlags flags)
        {
            if (data == IntPtr.Zero)
                throw new ArgumentNullException("data");

            if (length < 0)
                throw new ArgumentOutOfRangeException();

            nativePacket = Native.enet_packet_create(data, (IntPtr)length, flags);
        }

        public void CopyTo(byte[] destination)
        {
            if (destination == null)
                throw new ArgumentNullException("destination");

            Marshal.Copy(Data, destination, 0, Length);
        }

        #region IDisposable

        public void Dispose()
        {
            if (nativePacket != IntPtr.Zero)
            {
                Native.enet_packet_dispose(nativePacket);
                nativePacket = IntPtr.Zero;
            }
        }

        #endregion
    }


    public class Host: IDisposable
    {
        internal IntPtr nativeHost;

        public bool IsValid
        {
            get { return nativeHost != IntPtr.Zero; }
        }

        public uint PeersCount
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_peers_count(nativeHost);
            }
        }

        public uint PacketsSent
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_packets_sent(nativeHost);
            }
        }

        public uint PacketsReceived
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_packets_received(nativeHost);
            }
        }

        public uint BytesSent
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_bytes_sent(nativeHost);
            }
        }

        public uint BytesReceived
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_bytes_received(nativeHost);
            }
        }

        private void ThrowIfChannelLimitOutOfRange(byte channelLimit)
        {
            if (channelLimit < 0 || channelLimit > Protocol.maxChannelCount)
                throw new ArgumentOutOfRangeException("channelLimit");
        }

        internal void ThrowIfNotValid()
        {
            if (!IsValid)
                throw new InvalidOperationException("Host not created");
        }

        public void Create()
        {
            Create(null, 1, 0);
        }

        public void Create(Address? address, int peerLimit)
        {
            Create(address, peerLimit, 0);
        }

        public void Create(Address? address, int peerLimit, byte channelLimit)
        {
            Create(address, peerLimit, channelLimit, 0, 0);
        }

        public void Create(int peerLimit, byte channelLimit, uint incomingBandwidth, uint outgoingBandwidth)
        {
            Create(null, peerLimit, channelLimit, incomingBandwidth, outgoingBandwidth);
        }

        public void Create(Address? address, int peerLimit, byte channelLimit, uint incomingBandwidth, uint outgoingBandwidth)
        {
            if (nativeHost != IntPtr.Zero)
                throw new InvalidOperationException("Host already created");

            if (peerLimit < 0 || peerLimit > Protocol.maxPeers)
                throw new ArgumentOutOfRangeException("peerLimit");

            ThrowIfChannelLimitOutOfRange(channelLimit);

            if (address != null)
            {
                var nativeAddress = address.Value.nativeAddress;

                nativeHost = Native.enet_host_create(ref nativeAddress, (IntPtr)peerLimit, channelLimit, incomingBandwidth, outgoingBandwidth);
            }
            else
            {
                nativeHost = Native.enet_host_create(IntPtr.Zero, (IntPtr)peerLimit, channelLimit, incomingBandwidth, outgoingBandwidth);
            }

            if (nativeHost == IntPtr.Zero)
                throw new InvalidOperationException("Host creation call failed");
        }

        public bool CompressionEnabled
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_compression_enabled(nativeHost) > 0;
            }

            set
            {
                ThrowIfNotValid();
                Native.enet_host_set_compression_enabled(nativeHost, (byte)(value ? 1 : 0));
            }
        }

        public bool CrcEnabled
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_crc_enabled(nativeHost) > 0;
            }

            set
            {
                ThrowIfNotValid();
                Native.enet_host_set_crc_enabled(nativeHost, (byte)(value ? 1 : 0));
            }
        }

        public bool RefuseConnections
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_refuse_connections(nativeHost) > 0;
            }

            set
            {
                ThrowIfNotValid();
                Native.enet_host_set_refuse_connections(nativeHost, (byte)(value ? 1 : 0));
            }
        }

        public void Broadcast(byte channelId, ref Packet packet)
        {
            ThrowIfNotValid();
            packet.ThrowIfNotValid();

            Native.enet_host_broadcast(nativeHost, channelId, packet.NativeData);
            packet.NativeData = IntPtr.Zero;
        }

        public int CheckEvents(out Event ev)
        {
            ThrowIfNotValid();

            ENetEvent nativeEvent;
            int result = Native.enet_host_check_events(nativeHost, out nativeEvent);
            ev = (result <= 0) ? default(Event) : new Event(nativeEvent);

            return result;
        }

        public Peer Connect(Address address)
        {
            return Connect(address, 0, 0);
        }

        public Peer Connect(Address address, byte channelLimit)
        {
            return Connect(address, channelLimit, 0);
        }

        public Peer Connect(Address address, byte channelLimit, uint data)
        {
            ThrowIfNotValid();
            ThrowIfChannelLimitOutOfRange(channelLimit);

            var nativeAddress = address.nativeAddress;
            var peer = new Peer(Native.enet_host_connect(nativeHost, ref nativeAddress, channelLimit, data));

            if (peer.NativeData == IntPtr.Zero)
                throw new InvalidOperationException("Host connect call failed");

            return peer;
        }

        public int Service(out Event ev, int timeout = 0)
        {
            if (timeout < 0)
                throw new ArgumentOutOfRangeException("timeout");

            ThrowIfNotValid();

            ENetEvent nativeEvent;
            int result = Native.enet_host_service(nativeHost, out nativeEvent, (uint)timeout);
            ev = (result <= 0) ? default(Event) : new Event(nativeEvent);

            return result;
        }

        public void SetBandwidthLimit(uint incomingBandwidth, uint outgoingBandwidth)
        {
            ThrowIfNotValid();

            Native.enet_host_bandwidth_limit(nativeHost, incomingBandwidth, outgoingBandwidth);
        }

        public void SetChannelLimit(byte channelLimit)
        {
            ThrowIfNotValid();
            ThrowIfChannelLimitOutOfRange(channelLimit);

            Native.enet_host_channel_limit(nativeHost, channelLimit);
        }

        public void Flush()
        {
            ThrowIfNotValid();

            Native.enet_host_flush(nativeHost);
        }

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (nativeHost != IntPtr.Zero)
            {
                Native.enet_host_destroy(nativeHost);
                nativeHost = IntPtr.Zero;
            }
        }

        ~Host()
        {
            Dispose(false);
        }

        #endregion
    }

    public struct Peer
    {
        internal IntPtr nativePeer;

        private uint nativeId;

        internal Peer(IntPtr peer)
        {
            nativePeer = peer;
            nativeId = nativePeer != IntPtr.Zero ? Native.enet_peer_get_id(nativePeer) : 0;
        }

        public bool IsValid
        {
            get { return nativePeer != IntPtr.Zero; }
        }

        public uint Id
        {
            get { return nativeId; }
        }

        public string IpAddress
        {
            get
            {
                ThrowIfNotValid();

                byte[] ip = ArrayPool.GetBuffer();

                if (Native.enet_peer_get_ip(nativePeer, ip, (IntPtr)ip.Length) == 0)
                {
                    if (Encoding.ASCII.GetString(ip).Remove(7) != "::ffff:")
                        return Encoding.ASCII.GetString(ip, 0, ip.AnsiStrLen());
                    else
                        return Encoding.ASCII.GetString(ip, 0, ip.AnsiStrLen()).Substring(7);
                }
                else
                {
                    return string.Empty;
                }
            }
        }

        public ushort Port
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_port(nativePeer);
            }
        }

        public uint Mtu
        {
            get
            {
                ThrowIfNotValid();

                return Native.enet_peer_get_mtu(nativePeer);
            }
        }

        public PeerState State
        {
            get { return nativePeer == IntPtr.Zero ? PeerState.Uninitialized : Native.enet_peer_get_state(nativePeer); }
        }

        public uint RoundTripTime
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_rtt(nativePeer);
            }
        }

        public uint LastSendTime
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_lastsendtime(nativePeer);
            }
        }

        public uint LastReceiveTime
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_lastreceivetime(nativePeer);
            }
        }

        public ulong PacketsSent
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_packets_sent(nativePeer);
            }
        }

        public uint PacketsLost
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_packets_lost(nativePeer);
            }
        }

        public ulong BytesSent
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_bytes_sent(nativePeer);
            }
        }

        public ulong BytesReceived
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_bytes_received(nativePeer);
            }
        }

        public IntPtr Data
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_data(nativePeer);
            }

            set
            {
                ThrowIfNotValid();
                Native.enet_peer_set_data(nativePeer, value);
            }
        }

        internal void ThrowIfNotValid()
        {
            if (nativePeer == IntPtr.Zero)
                throw new InvalidOperationException("Peer not created");
        }

        public void ConfigureThrottle(uint interval, uint acceleration, uint deceleration)
        {
            ThrowIfNotValid();
            Native.enet_peer_throttle_configure(nativePeer, interval, acceleration, deceleration);
        }

        public bool Send(byte channelID, ref Packet packet)
        {
            ThrowIfNotValid();
            packet.ThrowIfNotValid();
            return Native.enet_peer_send(nativePeer, channelID, packet.NativeData) == 0;
        }

        public void Ping()
        {
            ThrowIfNotValid();
            Native.enet_peer_ping(nativePeer);
        }

        public uint PingInterval
        {
            get
            {
                ThrowIfNotValid();
                Native.enet_peer_set_ping_interval(nativePeer, interval);
            }

            set
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_ping_interval(nativePeer);
            }
        }

        public void Timeout(uint timeoutLimit, uint timeoutMinimum, uint timeoutMaximum)
        {
            ThrowIfNotValid();
            Native.enet_peer_timeout(nativePeer, timeoutLimit, timeoutMinimum, timeoutMaximum);
        }

        public void Disconnect(uint data)
        {
            ThrowIfNotValid();
            Native.enet_peer_disconnect(nativePeer, data);
        }

        public void DisconnectImmediately(uint data)
        {
            ThrowIfNotValid();
            Native.enet_peer_disconnect_immediately(nativePeer, data);
        }

        public void DisconnectWhenReady(uint data)
        {
            ThrowIfNotValid();
            Native.enet_peer_disconnect_when_ready(nativePeer, data);
        }

        public void Reset()
        {
            ThrowIfNotValid();
            Native.enet_peer_reset(nativePeer);
        }
    }

    public static class Protocol
    {
        public const ushort MaxChannelCount = 256;
        public const ushort MaxPeers = 4096;
        public const uint MaxPacketSize = 32 * 1024 * 1024;
        public const uint ThrottleScale = 32;
        public const uint DefaultThrottleAcceleration = 2;
        public const uint DefaultThrottleDeceleration = 2;
        public const uint DefaultThrottleInterval = 5000;
        public const uint DefaultTimeoutLimit = 32;
        public const uint DefaultTimeoutMinimum = 5000;
        public const uint DefaultTimeoutMaximum = 30000;

        public static bool Initialize()
        {
            return Native.enet_initialize() == 0;
        }

        public static bool Initialize(Callbacks callbacks)
        {
            return Native.enet_initialize_with_callbacks(version, ref callbacks.nativeCallbacks) == 0;
        }

        public static void Deinitialize()
        {
            Native.enet_deinitialize();
        }

        public static ulong Time
        {
            get { return Native.enet_time_get(); }
        }
    }

    [SuppressUnmanagedCodeSecurity]
    internal static class Native
    {
        #if __IOS__ || UNITY_IOS && !UNITY_EDITOR
            private const string nativeLibrary = "__Internal";
        #else
            private const string nativeLibrary = "libenet";
        #endif

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_initialize();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_initialize_with_callbacks(uint version, ref ENetCallbacks callbacks);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_deinitialize();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_time_get();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_address_set_host(ref ENetAddress address, byte[] hostName);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_address_get_host(ref ENetAddress address, byte[] hostName, IntPtr length);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_packet_create(byte[] data, IntPtr dataLength, PacketFlags flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_packet_create(IntPtr data, IntPtr dataLength, PacketFlags flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_packet_get_data(IntPtr packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_packet_get_length(IntPtr packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_packet_set_free_callback(IntPtr packet, IntPtr callback);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_packet_dispose(IntPtr packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_host_create(ref ENetAddress address, IntPtr peerLimit, byte channelLimit, uint incomingBandwidth, uint outgoingBandwidth);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_host_create(IntPtr address, IntPtr peerLimit, byte channelLimit, uint incomingBandwidth, uint outgoingBandwidth);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_host_connect(IntPtr host, ref ENetAddress address, byte channelCount, uint data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_broadcast(IntPtr host, byte channelID, IntPtr packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_host_service(IntPtr host, out ENetEvent ev, uint timeout);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_host_check_events(IntPtr host, out ENetEvent ev);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_channel_limit(IntPtr host, byte channelLimit);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_bandwidth_limit(IntPtr host, uint incomingBandwidth, uint outgoingBandwidth);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_peers_count(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_packets_sent(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_packets_received(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_bytes_sent(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_bytes_received(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_flush(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_destroy(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_set_compression_enabled(IntPtr host, byte value);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern byte enet_host_get_compression_enabled(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_set_crc_enabled(IntPtr host, byte value);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern byte enet_host_get_crc_enabled(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_set_refuse_connections(IntPtr host, byte value);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern byte enet_host_get_refuse_connections(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_throttle_configure(IntPtr peer, uint interval, uint acceleration, uint deceleration);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_id(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_peer_get_ip(IntPtr peer, byte[] ip, IntPtr length);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ushort enet_peer_get_port(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_mtu(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern PeerState enet_peer_get_state(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_rtt(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_lastsendtime(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_lastreceivetime(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_peer_get_packets_sent(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_packets_lost(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_peer_get_bytes_sent(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_peer_get_bytes_received(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_peer_get_data(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_set_data(IntPtr peer, IntPtr data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_peer_send(IntPtr peer, byte channelId, IntPtr packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_ping(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_set_ping_interval(IntPtr peer, uint value);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_ping_interval(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_timeout(IntPtr peer, uint timeoutLimit, uint timeoutMinimum, uint timeoutMaximum);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_disconnect(IntPtr peer, uint data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_disconnect_immediately(IntPtr peer, uint data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_disconnect_when_ready(IntPtr peer, uint data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_reset(IntPtr peer);
    }

    internal static class ByteArrayExtensions
    {
        public static int AnsiStrLen(this byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            int i;
            for (i = 0; i < data.Length && data[i] != 0; i++)
                ;
            return i;
        }
    }
}
