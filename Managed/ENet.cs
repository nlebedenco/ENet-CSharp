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
    public enum PacketFlags: ushort
    {
        /// <summary>
        /// Ordered but unreliable packets unless fragmented (fragments are reliable by default)
        /// </summary>
        None = 0,
        /// <summary>
        /// Ordered and reliable packets
        /// </summary>
        Reliable = 1 << 0,
        /// <summary>
        /// Unordered and unreliable packets unless fragmented (fragments are reliable by default)
        /// </summary>
        Unsequenced = 1 << 1,
        /// <summary>
        /// Packet has custom allocator (internal use only)
        /// </summary>
        NoAllocate = 1 << 2,
        /// <summary>
        /// Unreliable fragments
        /// </summary>
        UnreliableFragments = 1 << 3
    }

    public enum EventType
    {
        None = 0,
        Connect = 1,
        Disconnect = 2,
        Data = 3,
        Timeout = 4
    }

    public enum PeerState
    {
        Invalid = -1,
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

    internal enum ErrorCode
    {
        None = 0,
        Unspecified = -1,
        InvalidOperation = -2,
        InvalidArguments = -3,
        OutOfMemory = -4,
        ReceiveIncomingPacketsFailed = -10,
        DispatchIncomingPacketsFailed = -11,
        SendOutgoingCommandsFailed = -12,
        SocketWaitFailed = -13
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENetAddress
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Host;
        public ushort Port;
        public ushort ScopeId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENetEvent
    {
        public EventType Type;
        public IntPtr Peer;
        public byte ChannelId;
        public uint Status;
        public IntPtr Packet;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENetCallbacks
    {
        public IntPtr Malloc;
        public IntPtr Free;
        public IntPtr OutOfMemory;
    }

    public delegate IntPtr AllocCallback(IntPtr size);
    public delegate void FreeCallback(IntPtr memory);
    public delegate void OutOfMemoryCallback();

    internal static class StaticMemory
    {
        [ThreadStatic]
        public static readonly byte[] Buffer = new byte[128];
    }

    public struct Address
    {
        internal ENetAddress nativeAddress;

        public static Address Localhost(ushort port)
        {
            Address address = default(Address);
            Native.enet_address_localhost(ref address.nativeAddress, port);
            return address;
        }

        public static Address Anyhost(ushort port)
        {
            Address address = default(Address);
            Native.enet_address_anyhost(ref address.nativeAddress, port);
            return address;
        }

        public Address(string host, ushort port)
        {
            this.nativeAddress = default(ENetAddress);
            if (string.IsNullOrEmpty(host))
            {
                Native.enet_address_anyhost(ref nativeAddress, port);
            }
            else
            {
                this.Host = host;
                this.Port = port;
            }
        }

        public string Host
        {
            get
            {
                byte[] hostName = StaticMemory.Buffer;

                if (Native.enet_address_get_name(ref nativeAddress, hostName, (IntPtr)hostName.Length) == 0)
                    return Encoding.ASCII.GetString(hostName, 0, hostName.AnsiStrLen());
                else
                    return string.Empty;
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(value));

                if (Native.enet_address_set_name(ref nativeAddress, Encoding.ASCII.GetBytes(value)) != 0)
                    throw new ArgumentException("Name cannot be resolved", nameof(value)); 
            }
        }

        public string Ip
        {
            get
            {
                byte[] ip = StaticMemory.Buffer;

                if (Native.enet_address_get_ip(ref nativeAddress, ip, (IntPtr)ip.Length) == 0)
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
            get { return nativeAddress.Port; }

            set { nativeAddress.Port = value; }
        }
    }

    public struct Event
    {
        private ENetEvent nativeEvent;

        internal Event(ENetEvent nativeEvent)
        {
            this.nativeEvent = nativeEvent;
        }

        public EventType Type => nativeEvent.Type;
        public Peer Peer => new Peer(nativeEvent.Peer);
        public byte ChannelId => nativeEvent.ChannelId;
        public uint Status => nativeEvent.Status;
        public Packet Packet => new Packet(nativeEvent.Packet);
    }

    public struct Callbacks
    {
        internal ENetCallbacks nativeCallbacks;

        public Callbacks(AllocCallback allocCallback, FreeCallback freeCallback, OutOfMemoryCallback outOfMemoryCallback)
        {
            nativeCallbacks.Malloc = Marshal.GetFunctionPointerForDelegate(allocCallback);
            nativeCallbacks.Free = Marshal.GetFunctionPointerForDelegate(freeCallback);
            nativeCallbacks.OutOfMemory = Marshal.GetFunctionPointerForDelegate(outOfMemoryCallback);
        }
    }

    public struct Packet : IDisposable
    {
        public static Packet Create(byte[] data, PacketFlags flags = PacketFlags.None)
        {
            return Create(data, data.Length, flags);
        }

        public static Packet Create(byte[] data, int length, PacketFlags flags = PacketFlags.None)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (length < 0 || length > data.Length)
                throw new ArgumentOutOfRangeException(nameof(length));

            return new Packet(Native.enet_packet_create(data, (IntPtr)length, flags));
        }

        public static Packet Create(byte[] data, int index, int length, PacketFlags flags = PacketFlags.None)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (index < 0 || index >= data.Length)
                throw new ArgumentOutOfRangeException(nameof(index));

            if (length < 0 || (index + length) > data.Length)
                throw new ArgumentOutOfRangeException(nameof(length));

            return new Packet(Native.enet_packet_create_offset(data, (IntPtr)length, (IntPtr)index, flags));
        }

        internal Packet(IntPtr packet)
        {
            nativePacket = packet;
        }

        internal IntPtr nativePacket;

        public bool IsValid
        {
            get { return nativePacket != IntPtr.Zero; }
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
                throw new InvalidOperationException("Packet is not valid");
        }

        public void CopyTo(byte[] destination)
        {
            if (destination == null)
                throw new ArgumentNullException(nameof(destination));

            ThrowIfNotValid();

            IntPtr nativeData = Native.enet_packet_get_data(nativePacket);
            Marshal.Copy(nativeData, destination, 0, Length);
        }

        public byte[] ToArray()
        {
            ThrowIfNotValid();

            IntPtr nativeData = Native.enet_packet_get_data(nativePacket);
            int n = Length;
            byte[] array = new byte[n];
            if (n > 0)
                Marshal.Copy(nativeData, array, 0, n);

            return array;
        }

        #region IDisposable

        /// <summary>
        /// Dispose of any resources allocated by this packet. It's always safe to call this method
        /// even if the packet is invalid or has been already disposed.
        /// </summary>
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

    public sealed class Host: IDisposable 
    {
        /// <summary>
        /// Create a client host not bound to any specific local address. Local port is a random free port and maximum number of outgoing connections is 1.
        /// </summary>
        public static Host Create(ushort channelCount = Runtime.MinChannelCount, uint incomingBandwidth = 0, uint outgoingBandwidth = 0)
        {
            ThrowIfChannelCountOutOfRange(channelCount);
            var nativeHost = Native.enet_host_create(IntPtr.Zero, (IntPtr)1, channelCount, incomingBandwidth, outgoingBandwidth);
            if (nativeHost == IntPtr.Zero)
                throw new OutOfMemoryException("Not enough memory to create Host.");

            return new Host(nativeHost);
        }

        /// <summary>
        /// Create a server host bound to a specific local address and port.
        /// </summary>
        public static Host Create(Address bindAddress, int peerLimit = 8, ushort channelCount = Runtime.MinChannelCount, uint incomingBandwidth = 0, uint outgoingBandwidth = 0)
        {
            if (peerLimit < 1 || peerLimit > Runtime.MaxPeers)
                throw new ArgumentOutOfRangeException(nameof(peerLimit));

            ThrowIfChannelCountOutOfRange(channelCount);

            var nativeAddress = bindAddress.nativeAddress;
            var nativeHost = Native.enet_host_create(ref nativeAddress, (IntPtr)peerLimit, channelCount, incomingBandwidth, outgoingBandwidth);

            if (nativeHost == IntPtr.Zero)
                throw new OutOfMemoryException("Not enough memory to create Host.");

            return new Host(nativeHost);
        }

        /// <summary>
        /// Create a server host bound to a specific local address and port.
        /// </summary>
        public static Host Create(string host, ushort port, int peerLimit = 8, ushort channelCount = Runtime.MinChannelCount, uint incomingBandwidth = 0, uint outgoingBandwidth = 0)
        {
            return Create(new Address(host, port), peerLimit, channelCount, incomingBandwidth, outgoingBandwidth);
        }

        private Host(IntPtr nativeHost)
        {
            this.nativeHost = nativeHost;
        }

        internal IntPtr nativeHost;

        public bool IsValid
        {
            get { return nativeHost != IntPtr.Zero; }
        }

        public int Count
        {
            get
            {
                ThrowIfNotValid();
                return unchecked((int)Native.enet_host_get_peers_count(nativeHost));
            }
        }

        public int Capacity
        {
            get
            {
                ThrowIfNotValid();
                return unchecked((int)Native.enet_host_get_peers_capacity(nativeHost));
            }
        }

        public Peer this[int index]
        {
            get
            {
                ThrowIfNotValid();
                IntPtr nativePeer = Native.enet_host_get_peer(nativeHost, unchecked((uint)index));
                if (nativePeer == IntPtr.Zero)
                    throw new IndexOutOfRangeException();

                return new Peer(nativePeer);
            }
        }

        public ulong PacketsSent
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_packets_sent(nativeHost);
            }
        }

        public ulong PacketsReceived
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_packets_received(nativeHost);
            }
        }

        public ulong BytesSent
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_bytes_sent(nativeHost);
            }
        }

        public ulong BytesReceived
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_bytes_received(nativeHost);
            }
        }

        public ulong StartTime
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_start_time(nativeHost);
            }
        }

        public TimeSpan Uptime
        {
            get
            {
                ThrowIfNotValid();
                return TimeSpan.FromMilliseconds(Native.enet_time() - Native.enet_host_get_start_time(nativeHost));
            }
        }

        private static void ThrowIfChannelCountOutOfRange(ushort channelCount)
        {
            if (channelCount < Runtime.MinChannelCount || channelCount > Runtime.MaxChannelCount)
                throw new ArgumentOutOfRangeException(nameof(channelCount));
        }

        private void ThrowIfNotValid()
        {
            if (!IsValid)
                throw new InvalidOperationException("Host is not valid");
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

        public ushort MaxChannelCount
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_host_get_channel_limit(nativeHost);
            }

            set
            {
                ThrowIfNotValid();
                ThrowIfChannelCountOutOfRange(value);
                Native.enet_host_set_channel_limit(nativeHost, value);
            }
        }

        public void SetBandwidthLimit(uint incomingBandwidth, uint outgoingBandwidth)
        {
            ThrowIfNotValid();

            Native.enet_host_bandwidth_limit(nativeHost, incomingBandwidth, outgoingBandwidth);
        }

        public Peer Connect(Address address, ushort channelCount = Runtime.MinChannelCount, uint status = 0)
        {
            ThrowIfNotValid();
            ThrowIfChannelCountOutOfRange(channelCount);

            var nativeAddress = address.nativeAddress;
            return new Peer(Native.enet_host_connect(nativeHost, ref nativeAddress, channelCount, status));
        }

        public Peer Connect(string host, ushort port, ushort channelCount = Runtime.MinChannelCount, uint status = 0)
        {
            return Connect(new Address(host, port), channelCount, status);
        }

        public void Disconnect(uint status = 0)
        {
            ThrowIfNotValid();
            uint peerCount = Native.enet_host_get_peers_count(nativeHost);
            for (uint i = 0; i < peerCount; ++i)
            {
                var nativePeer = Native.enet_host_get_peer(nativeHost, i);
                Native.enet_peer_disconnect(nativePeer, status);
            }
        }

        public void DisconnectImmediately(uint status = 0)
        {
            ThrowIfNotValid();
            uint peerCount = Native.enet_host_get_peers_count(nativeHost);
            for (uint i = 0; i < peerCount; ++i)
            {
                var nativePeer = Native.enet_host_get_peer(nativeHost, i);
                Native.enet_peer_disconnect_immediately(nativePeer, status);
                Peer.ReleaseUserData(nativePeer);
            }
        }

        public void DisconnectWhenReady(uint status = 0)
        {
            ThrowIfNotValid();
            uint peerCount = Native.enet_host_get_peers_count(nativeHost);
            for (uint i = 0; i < peerCount; ++i)
            {
                var nativePeer = Native.enet_host_get_peer(nativeHost, i);
                Native.enet_peer_disconnect_when_ready(nativePeer, status);
            }
        }

        /// <summary>
        /// Broadcast packet to all connected peers. The packet is transfered to the runtime
        /// library and becomes invalid after a successful call to this method.
        /// </summary>
        public void Broadcast(byte channelId, ref Packet packet)
        {
            ThrowIfNotValid();
            packet.ThrowIfNotValid();

            Native.enet_host_broadcast(nativeHost, channelId, packet.nativePacket);
            // Once the packet is handed over, ENet will handle its deallocation.
            // This effectively invalidates the packet. Any call to Dispose
            // will have no effect. Other methods and properties will
            // throw an exception.
            packet.nativePacket = IntPtr.Zero;
        }

        public void Update(out Event netEvent, uint timeout = 0)
        {
            ThrowIfNotValid();

            int errcode = Native.enet_host_service(nativeHost, out ENetEvent nativeEvent, timeout);
            Native.ThrowIfError(errcode);
            netEvent = new Event(nativeEvent);
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

        private void Dispose(bool disposing)
        {
            if (nativeHost != IntPtr.Zero)
            {
                uint peerCount = Native.enet_host_get_peers_count(nativeHost);
                for (uint i = 0; i < peerCount; ++i)
                    Peer.ReleaseUserData(Native.enet_host_get_peer(nativeHost, i));

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
        internal static void ReleaseUserData(IntPtr nativePeer)
        {
            IntPtr userDataPtr = Native.enet_peer_get_userdata(nativePeer);
            if (userDataPtr != IntPtr.Zero)
            {
                GCHandle.FromIntPtr(userDataPtr).Free();
                Native.enet_peer_set_userdata(nativePeer, IntPtr.Zero);
            }
        }

        private readonly IntPtr nativePeer;

        internal Peer(IntPtr nativePeer)
        {
            this.nativePeer = nativePeer;
            if (nativePeer != IntPtr.Zero)
            {
                Id = Native.enet_peer_get_id(nativePeer);
                LocalIndex = Native.enet_peer_get_incoming_id(nativePeer);
                RemoteIndex = Native.enet_peer_get_outgoing_id(nativePeer);
            }
            else
            {
                Id = 0;
                LocalIndex = 0;
                RemoteIndex = 0;
            }
            
        }

        public uint Id { get; }

        public ushort LocalIndex { get; }

        public ushort RemoteIndex { get; }

        public string IpAddress
        {
            get
            {
                ThrowIfNotValid();

                byte[] ip = StaticMemory.Buffer;

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

        public string Hostname
        {
            get
            {
                ThrowIfNotValid();

                byte[] name = StaticMemory.Buffer;

                if (Native.enet_peer_get_name(nativePeer, name, (IntPtr)name.Length) == 0)
                    return Encoding.ASCII.GetString(name, 0, name.AnsiStrLen());
                else
                    return string.Empty;
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

        public ushort Mtu
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_mtu(nativePeer);
            }
        }

        public PeerState State
        {
            get { return nativePeer == IntPtr.Zero ? PeerState.Invalid : Native.enet_peer_get_state(nativePeer); }
        }

        public ushort ChannelCount
        {
            get
            {
                ThrowIfNotValid();
                return Native.enet_peer_get_channel_count(nativePeer);
            }
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

        public ulong PacketsLost
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

        /// <summary>
        /// Custom application data that may be freely modified. Must be assigned null when no longer needed
        /// (generally after either a disconnect or reset) in order for the referenced object to be garbage collected.
        /// </summary>
        public object UserData
        {
            get
            {
                ThrowIfNotValid();
                var ptr = Native.enet_peer_get_userdata(nativePeer);
                return ptr == IntPtr.Zero ? null : GCHandle.FromIntPtr(ptr).Target;
            }

            set
            {
                ThrowIfNotValid();
                ReleaseUserData(nativePeer);

                if (value != null)
                {
                    var handle = GCHandle.Alloc(value, GCHandleType.Normal);
                    Native.enet_peer_set_userdata(nativePeer, GCHandle.ToIntPtr(handle));
                }
            }
        }

        public object ReleaseUserData()
        {
            ThrowIfNotValid();

            object value = null;

            var userDataPtr = Native.enet_peer_get_userdata(nativePeer);
            if (userDataPtr != IntPtr.Zero)
            {
                var handle = GCHandle.FromIntPtr(userDataPtr);
                value = handle.Target;
                handle.Free();
                Native.enet_peer_set_userdata(nativePeer, IntPtr.Zero);
            }

            return value;
        }

        public void ConfigureThrottle(uint interval, uint acceleration, uint deceleration)
        {
            ThrowIfNotValid();
            Native.enet_peer_throttle_configure(nativePeer, interval, acceleration, deceleration);
        }

        /// <summary>
        /// Send a packet over the specified channel. The packet is transfered to the runtime
        /// library and becomes invalid after a successful call to this method.
        /// </summary>
        public void Send(byte channelId, ref Packet packet)
        {
            ThrowIfNotValid();
            packet.ThrowIfNotValid();

            ushort channelCount = Native.enet_peer_get_channel_count(nativePeer);
            if (channelId >= channelCount)
                throw new ArgumentOutOfRangeException(nameof(channelId));

            int errcode = Native.enet_peer_send(nativePeer, channelId, packet.nativePacket);
            Native.ThrowIfError(errcode);

            // Once the packet is handed over, ENet will handle its deallocation.
            // This effectively invalidates the packet. Any call to Dispose
            // will have no effect. Other methods and properties will
            // throw an exception.
            packet.nativePacket = IntPtr.Zero;
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
                return Native.enet_peer_get_ping_interval(nativePeer);
            }

            set
            {
                ThrowIfNotValid();
                Native.enet_peer_set_ping_interval(nativePeer, value);
            }
        }

        public void SetTimeout(uint timeoutLimit, uint timeoutMinimum, uint timeoutMaximum)
        {
            ThrowIfNotValid();
            Native.enet_peer_timeout(nativePeer, timeoutLimit, timeoutMinimum, timeoutMaximum);
        }

        /// <summary>
        /// Disconnect upon confirmation. A disconnect command is sent to the remote peer and a confirmation is expected.
        /// Either a disconnect or a timeout event will be raised for this peer. UserData must then be explicitly released
        /// (by assigning null)
        /// </summary>
        public void Disconnect(uint status = 0)
        {
            if (nativePeer != IntPtr.Zero)
                Native.enet_peer_disconnect(nativePeer, status);
        }

        /// <summary>
        /// Immediately disconnect. An unsequenced disconnect command is sent to the remote peer and the output queue is flushed.
        /// No confirmation is expected and no further events will be raised for this peer not even a disconnect event.
        /// UserData if any is automatically released before the disconnection.
        /// </summary>
        public void DisconnectImmediately(uint status = 0)
        {
            if (nativePeer != IntPtr.Zero)
            {
                ReleaseUserData(nativePeer);
                Native.enet_peer_disconnect_immediately(nativePeer, status);
            }
        }

        /// <summary>
        /// Disconnect after all outgoing packets and pending confirmations are handled. A disconnect command is sent to the remote peer
        /// and confirmation is expected. Either a disconnect or a timeout event will be raised for this peer. UserData must then be
        /// explicitly released (by assigning null)
        /// </summary>
        public void DisconnectWhenReady(uint status = 0)
        {
            if (nativePeer != IntPtr.Zero)
                Native.enet_peer_disconnect_when_ready(nativePeer, status);
        }

        /// <summary>
        /// Immediately reset the peer. All buffers are immediately discarded and no notification is sent to the remote end. 
        /// No further events will be raised for this peer not even a disconnect event.
        /// UserData if any gets released before the disconnection.
        /// </summary>
        public void Reset()
        {
            if (nativePeer != IntPtr.Zero)
            {
                ReleaseUserData(nativePeer);
                Native.enet_peer_reset(nativePeer);
            }
        }

        private void ThrowIfNotValid()
        {
            if (nativePeer == IntPtr.Zero)
                throw new InvalidOperationException("Peer is not valid");
        }
    }

    public static class Runtime
    {
        public const ushort MinChannelCount = 1;
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

        public static Version Version => System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;

        public static Version NativeLibraryVersion { get; private set; }
        
        public static void Initialize()
        {
            if (Native.enet_initialize() != (int)ErrorCode.None)
                throw new ENetException("Native library initialization failed.");

            var nativeVersion = Native.enet_version();
            NativeLibraryVersion = new Version((int)(nativeVersion >> 48), (int)(nativeVersion >> 32) & 0x0000FFFF, (int)(nativeVersion >> 16) & 0x0000FFFF, (int)nativeVersion & 0x0000FFFF);
        }

        public static void Initialize(Callbacks callbacks)
        {
            int errcode = Native.enet_initialize_with_callbacks(ref callbacks.nativeCallbacks);
            switch ((ErrorCode)errcode)
            {
                case ErrorCode.None:
                    break;
                case ErrorCode.InvalidArguments:
                    throw new ENetException("Native library initialization failed.", new ArgumentException("One or more arguments are invalid."));
                default:
                    throw new ENetException("Native library initialization failed.");
            }
        }

        public static void Shutdown()
        {
            Native.enet_finalize();
        }

        public static ulong Time
        {
            get { return Native.enet_time(); }
        }
    }

    [SuppressUnmanagedCodeSecurity]
    internal static class Native
    {
        #if __IOS__ || (UNITY_IOS && !UNITY_EDITOR)
            private const string nativeLibrary = "__Internal";
        #else
            private const string nativeLibrary = "libenet3";
#endif

        internal static void ThrowIfError(int errcode)
        {
            if (errcode > 0)
                return;

            switch ((ErrorCode)errcode)
            {
                case ErrorCode.None:
                    break;
                case ErrorCode.InvalidOperation:
                    throw new InvalidOperationException();
                case ErrorCode.InvalidArguments:
                    throw new ArgumentException("One or more specified arguments are invalid.");
                case ErrorCode.OutOfMemory:
                    throw new OutOfMemoryException();
                case ErrorCode.ReceiveIncomingPacketsFailed:
                    throw new ENetReceiveIncomingPacketsException();
                case ErrorCode.DispatchIncomingPacketsFailed:
                    throw new ENetDispatchIncomingPacketsException();
                case ErrorCode.SendOutgoingCommandsFailed:
                    throw new ENetSendOutgoingCommandsException();
                case ErrorCode.SocketWaitFailed:
                    throw new ENetSocketWaitException();
                default:
                    throw new ENetException();
            }
        }

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_initialize();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_initialize_with_callbacks(ref ENetCallbacks callbacks);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_finalize();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long enet_version();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_time();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_address_localhost(ref ENetAddress address, ushort port);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_address_anyhost(ref ENetAddress address, ushort port);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_address_set_name(ref ENetAddress address, byte[] hostName);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_address_get_name(ref ENetAddress address, byte[] hostName, IntPtr length);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_address_get_ip(ref ENetAddress address, byte[] ip, IntPtr length);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_packet_create(byte[] data, IntPtr dataLength, PacketFlags flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_packet_create_offset(byte[] data, IntPtr dataLength, IntPtr dataOffset, PacketFlags flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_packet_get_data(IntPtr packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_packet_get_length(IntPtr packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_packet_dispose(IntPtr packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_host_create(ref ENetAddress address, IntPtr peerLimit, ushort channelCount, uint incomingBandwidth, uint outgoingBandwidth);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_host_create(IntPtr address, IntPtr peerLimit, ushort channelCount, uint incomingBandwidth, uint outgoingBandwidth);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_host_connect(IntPtr host, ref ENetAddress address, ushort channelCount, uint data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_broadcast(IntPtr host, byte channelId, IntPtr packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_host_service(IntPtr host, out ENetEvent ev, uint timeout);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_host_check_events(IntPtr host, out ENetEvent ev);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_set_channel_limit(IntPtr host, ushort value);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ushort enet_host_get_channel_limit(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_host_get_start_time(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_bandwidth_limit(IntPtr host, uint incomingBandwidth, uint outgoingBandwidth);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_host_get_peer(IntPtr host, uint index);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_peers_count(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_peers_capacity(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_host_get_packets_sent(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_host_get_packets_received(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_host_get_bytes_sent(IntPtr host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_host_get_bytes_received(IntPtr host);

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
        internal static extern ushort enet_peer_get_incoming_id(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ushort enet_peer_get_outgoing_id(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_peer_get_ip(IntPtr peer, byte[] ip, IntPtr length);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_peer_get_name(IntPtr peer, byte[] name, IntPtr length);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ushort enet_peer_get_port(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ushort enet_peer_get_mtu(IntPtr peer);

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
        internal static extern ulong enet_peer_get_packets_lost(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_peer_get_bytes_sent(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_peer_get_bytes_received(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr enet_peer_get_userdata(IntPtr peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_set_userdata(IntPtr peer, IntPtr data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ushort enet_peer_get_channel_count(IntPtr peer);
        
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
        internal static extern void enet_peer_disconnect(IntPtr peer, uint status);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_disconnect_immediately(IntPtr peer, uint status);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_disconnect_when_ready(IntPtr peer, uint status);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_reset(IntPtr peer);
    }

    internal static class ByteArrayExtensions
    {
        public static int AnsiStrLen(this byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            int i;
            for (i = 0; i < data.Length && data[i] != 0; i++)
                ;
            return i;
        }
    }


    #region Exceptions

    [Serializable()]
    public class ENetException: Exception
    {
        public ENetException() : base() { }
        public ENetException(string message) : base(message) { }
        public ENetException(string message, System.Exception inner) : base(message, inner) { }

        // A constructor is needed for serialization when an exception propagates from a .NET remoting server to a client. 
        protected ENetException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    [Serializable()]
    public class ENetReceiveIncomingPacketsException: ENetException
    {
        public ENetReceiveIncomingPacketsException() : base() { }
        public ENetReceiveIncomingPacketsException(string message) : base(message) { }
        public ENetReceiveIncomingPacketsException(string message, System.Exception inner) : base(message, inner) { }

        // A constructor is needed for serialization when an exception propagates from a .NET remoting server to a client. 
        protected ENetReceiveIncomingPacketsException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    [Serializable()]
    public class ENetDispatchIncomingPacketsException: ENetException
    {
        public ENetDispatchIncomingPacketsException() : base() { }
        public ENetDispatchIncomingPacketsException(string message) : base(message) { }
        public ENetDispatchIncomingPacketsException(string message, System.Exception inner) : base(message, inner) { }

        // A constructor is needed for serialization when an exception propagates from a .NET remoting server to a client. 
        protected ENetDispatchIncomingPacketsException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    [Serializable()]
    public class ENetSendOutgoingCommandsException: ENetException
    {
        public ENetSendOutgoingCommandsException() : base() { }
        public ENetSendOutgoingCommandsException(string message) : base(message) { }
        public ENetSendOutgoingCommandsException(string message, System.Exception inner) : base(message, inner) { }

        // A constructor is needed for serialization when an exception propagates from a .NET remoting server to a client. 
        protected ENetSendOutgoingCommandsException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    [Serializable()]
    public class ENetSocketWaitException: ENetException
    {
        public ENetSocketWaitException() : base() { }
        public ENetSocketWaitException(string message) : base(message) { }
        public ENetSocketWaitException(string message, System.Exception inner) : base(message, inner) { }

        // A constructor is needed for serialization when an exception propagates from a .NET remoting server to a client. 
        protected ENetSocketWaitException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    #endregion
}

