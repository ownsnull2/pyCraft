from collections import deque
from threading import RLock
import zlib
import threading
import socket
import timeit
import select
import sys
import json
import re

from .types import VarInt
from .packets import clientbound, serverbound
from . import packets, encryption
from .. import (
    utility, KNOWN_MINECRAFT_VERSIONS, SUPPORTED_MINECRAFT_VERSIONS,
    SUPPORTED_PROTOCOL_VERSIONS, PROTOCOL_VERSION_INDICES
)
from ..exceptions import (
    VersionMismatch, LoginDisconnect, IgnorePacket, InvalidState
)


STATE_STATUS = 1
STATE_PLAYING = 2


class ConnectionContext(object):
    def __init__(self, **kwds):
        self.protocol_version = kwds.get('protocol_version')

    def protocol_earlier(self, other_pv):
        return utility.protocol_earlier(self.protocol_version, other_pv)

    def protocol_earlier_eq(self, other_pv):
        return utility.protocol_earlier_eq(self.protocol_version, other_pv)

    def protocol_later(self, other_pv):
        return utility.protocol_earlier(other_pv, self.protocol_version)

    def protocol_later_eq(self, other_pv):
        return utility.protocol_earlier_eq(other_pv, self.protocol_version)

    def protocol_in_range(self, start_pv, end_pv):
        return (utility.protocol_earlier(self.protocol_version, end_pv) and
                utility.protocol_earlier_eq(start_pv, self.protocol_version))


class _ConnectionOptions(object):
    def __init__(self, address=None, port=None, compression_threshold=-1,
                 compression_enabled=False):
        self.address = address
        self.port = port
        self.compression_threshold = compression_threshold
        self.compression_enabled = compression_enabled


class Connection(object):
    def __init__(
        self,
        address,
        port=25565,
        auth_token=None,
        username=None,
        initial_version=None,
        allowed_versions=None,
        handle_exception=None,
        handle_exit=None,
        sock=None,
    ):
        self._write_lock = RLock()

        self.networking_thread = None
        self.new_networking_thread = None
        self.packet_listeners = []
        self.early_packet_listeners = []
        self.outgoing_packet_listeners = []
        self.early_outgoing_packet_listeners = []
        self._exception_handlers = []
        self.socket = sock
        self.file_object = None

        def proto_version(version):
            if isinstance(version, str):
                proto_version = SUPPORTED_MINECRAFT_VERSIONS.get(version)
            elif isinstance(version, int):
                proto_version = version
            else:
                proto_version = None
            if proto_version not in SUPPORTED_PROTOCOL_VERSIONS:
                raise ValueError('Unsupported version number: %r.' % version)
            return proto_version

        if allowed_versions is None:
            self.allowed_proto_versions = set(SUPPORTED_PROTOCOL_VERSIONS)
        else:
            allowed_versions = set(map(proto_version, allowed_versions))
            self.allowed_proto_versions = allowed_versions

        latest_allowed_proto = max(self.allowed_proto_versions,
                                   key=PROTOCOL_VERSION_INDICES.get)

        if initial_version is None:
            self.default_proto_version = latest_allowed_proto
        else:
            self.default_proto_version = proto_version(initial_version)

        self.context = ConnectionContext(protocol_version=latest_allowed_proto)

        self.options = _ConnectionOptions()
        self.options.address = address
        self.options.port = port
        self.auth_token = auth_token
        self.username = username
        self.connected = self.socket is not None

        self.handle_exception = handle_exception
        self.exception, self.exc_info = None, None
        self.handle_exit = handle_exit

        self.reactor = PacketReactor(self)
        self._outgoing_packet_queue = deque()

    def _start_network_thread(self):
        with self._write_lock:
            if self.networking_thread is not None and \
               not self.networking_thread.interrupt or \
               self.new_networking_thread is not None:
                raise InvalidState('A networking thread is already running.')
            elif self.networking_thread is None:
                self.networking_thread = NetworkingThread(self)
                self.networking_thread.start()
            else:
                self.new_networking_thread \
                    = NetworkingThread(self, previous=self.networking_thread)
                self.new_networking_thread.start()

    def write_packet(self, packet, force=False):
        packet.context = self.context
        if force:
            with self._write_lock:
                self._write_packet(packet)
        else:
            self._outgoing_packet_queue.append(packet)

    def listener(self, *packet_types, **kwds):
        def listener_decorator(handler_func):
            self.register_packet_listener(handler_func, *packet_types, **kwds)
            return handler_func

        return listener_decorator

    def exception_handler(self, *exc_types, **kwds):
        def exception_handler_decorator(handler_func):
            self.register_exception_handler(handler_func, *exc_types, **kwds)
            return handler_func

        return exception_handler_decorator

    def register_packet_listener(self, method, *packet_types, **kwds):
        outgoing = kwds.pop('outgoing', False)
        early = kwds.pop('early', False)
        target = self.packet_listeners if not early and not outgoing \
            else self.early_packet_listeners if early and not outgoing \
            else self.outgoing_packet_listeners if not early \
            else self.early_outgoing_packet_listeners
        target.append(packets.PacketListener(method, *packet_types, **kwds))

    def register_exception_handler(self, handler_func, *exc_types, **kwds):
        early = kwds.pop('early', False)
        assert not kwds, 'Unexpected keyword arguments: %r' % (kwds,)
        if early:
            self._exception_handlers.insert(0, (handler_func, exc_types))
        else:
            self._exception_handlers.append((handler_func, exc_types))

    def _pop_packet(self):
        if len(self._outgoing_packet_queue) == 0:
            return False
        else:
            self._write_packet(self._outgoing_packet_queue.popleft())
            return True

    def _write_packet(self, packet):
        try:
            for listener in self.early_outgoing_packet_listeners:
                listener.call_packet(packet)

            if self.options.compression_enabled:
                packet.write(self.socket, self.options.compression_threshold)
            else:
                packet.write(self.socket)

            for listener in self.outgoing_packet_listeners:
                listener.call_packet(packet)
        except IgnorePacket:
            pass

    def status(self, handle_status=None, handle_ping=False):
        with self._write_lock:
            self._check_connection()

            self._connect()
            self._handshake(next_state=STATE_STATUS)
            self._start_network_thread()

            do_ping = handle_ping is not False
            self.reactor = StatusReactor(self, do_ping=do_ping)

            if handle_status is False:
                self.reactor.handle_status = lambda *args, **kwds: None
            elif handle_status is not None:
                self.reactor.handle_status = handle_status

            if handle_ping is False:
                self.reactor.handle_ping = lambda *args, **kwds: None
            elif handle_ping is not None:
                self.reactor.handle_ping = handle_ping

            request_packet = serverbound.status.RequestPacket()
            self.write_packet(request_packet)

    def connect(self):
        with self._write_lock:
            self._check_connection()

            self.context.protocol_version \
                = max(self.allowed_proto_versions,
                      key=PROTOCOL_VERSION_INDICES.get)

            self.spawned = False
            self._connect()
            if len(self.allowed_proto_versions) == 1:
                self._handshake(next_state=STATE_PLAYING)
                login_start_packet = serverbound.login.LoginStartPacket()
                if self.auth_token:
                    login_start_packet.name = self.auth_token.profile.name
                else:
                    login_start_packet.name = self.username
                self.write_packet(login_start_packet)
                self.reactor = LoginReactor(self)
            else:
                self._handshake(next_state=STATE_STATUS)
                self.write_packet(serverbound.status.RequestPacket())
                self.reactor = PlayingStatusReactor(self)
            self._start_network_thread()

    def _check_connection(self):
        if self.networking_thread is not None and \
           not self.networking_thread.interrupt or \
           self.new_networking_thread is not None:
            raise InvalidState('There is an existing connection.')

    def _connect(self):
        self._outgoing_packet_queue = deque()

        if self.socket is None:
            info = socket.getaddrinfo(self.options.address, self.options.port,
                                      0, socket.SOCK_STREAM)
            def key(ai):
                return 0 if ai[0] == socket.AF_INET else \
                       1 if ai[0] == socket.AF_INET6 else 2
            ai_faml, ai_type, ai_prot, _ai_cnam, ai_addr = min(info, key=key)

            self.socket = socket.socket(ai_faml, ai_type, ai_prot)
            self.socket.connect(ai_addr)
            self.connected = True
        elif not self.connected:
             # If a socket was provided but we got disconnected somehow
             # before calling _connect
             raise InvalidState('Provided socket is not connected.')


        self.file_object = self.socket.makefile("rb", 0)
        self.options.compression_enabled = False
        self.options.compression_threshold = -1


    def disconnect(self, immediate=False):
        with self._write_lock:
            self.connected = False

            if not immediate and self.socket is not None:
                while self._pop_packet():
                    pass

            if self.new_networking_thread is not None:
                self.new_networking_thread.interrupt = True
            elif self.networking_thread is not None:
                self.networking_thread.interrupt = True

            if self.socket is not None:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except socket.error:
                    pass
                finally:
                    if self.file_object:
                        self.file_object.close()
                        self.file_object = None
                    self.socket.close()
                    self.socket = None

    def _handshake(self, next_state=STATE_PLAYING):
        handshake = serverbound.handshake.HandShakePacket()
        handshake.protocol_version = self.context.protocol_version
        handshake.server_address = self.options.address
        handshake.server_port = self.options.port
        handshake.next_state = next_state

        self.write_packet(handshake)

    def _handle_exception(self, exc, exc_info):
        final_handler = self.handle_exception

        try:
            if self.reactor.handle_exception(exc, exc_info):
                return
        except Exception as new_exc:
            exc, exc_info = new_exc, sys.exc_info()

        for handler, exc_types in self._exception_handlers:
            if not exc_types or isinstance(exc, exc_types):
                try:
                    handler(exc, exc_info)
                    caught = True
                    break
                except Exception as new_exc:
                    exc, exc_info = new_exc, sys.exc_info()
        else:
            caught = False

        if final_handler not in (None, False):
            try:
                final_handler(exc, exc_info)
            except Exception as new_exc:
                exc, exc_info = new_exc, sys.exc_info()

        try:
            exc.exc_info = exc_info
        except (TypeError, AttributeError):
            pass

        self.exception, self.exc_info = exc, exc_info

        if (self.new_networking_thread or self.networking_thread).interrupt:
            self.disconnect(immediate=True)

        if final_handler is None and not caught:
            exc_value, exc_tb = exc_info[1:]
            raise exc_value.with_traceback(exc_tb)

    def _version_mismatch(self, server_protocol=None, server_version=None):
        if server_protocol is None:
            server_protocol = KNOWN_MINECRAFT_VERSIONS.get(server_version)

        if server_protocol is None:
            vs = 'version' if server_version is None else \
                 ('version of %s' % server_version)
        else:
            vs = ('protocol version of %d' % server_protocol) + \
                 ('' if server_version is None else ' (%s)' % server_version)
        ss = 'supported, but not allowed for this connection' \
             if server_protocol in SUPPORTED_PROTOCOL_VERSIONS \
             else 'not supported'
        err = VersionMismatch("Server's %s is %s." % (vs, ss))
        err.server_protocol = server_protocol
        err.server_version = server_version
        raise err

    def _handle_exit(self):
        if not self.connected and self.handle_exit is not None:
            self.handle_exit()

    def _react(self, packet):
        try:
            for listener in self.early_packet_listeners:
                listener.call_packet(packet)
            self.reactor.react(packet)
            for listener in self.packet_listeners:
                listener.call_packet(packet)
        except IgnorePacket:
            pass


class NetworkingThread(threading.Thread):
    def __init__(self, connection, previous=None):
        threading.Thread.__init__(self)
        self.interrupt = False
        self.connection = connection
        self.name = "Networking Thread"
        self.daemon = True

        self.previous_thread = previous

    def run(self):
        try:
            if self.previous_thread is not None:
                if self.previous_thread.is_alive():
                    self.previous_thread.join()
                with self.connection._write_lock:
                    self.connection.networking_thread = self
                    self.connection.new_networking_thread = None
            self._run()
            self.connection._handle_exit()
        except Exception as e:
            self.interrupt = True
            self.connection._handle_exception(e, sys.exc_info())
        finally:
            with self.connection._write_lock:
                self.connection.networking_thread = None

    def _run(self):
        while not self.interrupt:
            num_packets = 0
            with self.connection._write_lock:
                try:
                    while not self.interrupt and self.connection._pop_packet():
                        num_packets += 1
                        if num_packets >= 300:
                            break
                    exc_info = None
                except (IOError, socket.error): # Added socket.error
                    exc_info = sys.exc_info()

                if self.connection._outgoing_packet_queue:
                    read_timeout = 0
                else:
                    read_timeout = 0.05

            # Check connection state before reading
            if not self.connection.connected or self.interrupt:
                 break

            packets_read = 0
            while packets_read < 50 and not self.interrupt:
                # Check again before potentially blocking read
                if not self.connection.connected:
                    break
                try:
                    packet = self.connection.reactor.read_packet(
                        self.connection.file_object, timeout=read_timeout)
                except (EOFError, IOError, socket.error): # Added socket.error
                    # Treat socket errors during read as a disconnect
                    exc_info = sys.exc_info()
                    self.interrupt = True # Ensure loop termination
                    break # Exit inner loop immediately
                if not packet:
                    break
                packets_read += 1
                self.connection._react(packet)
                read_timeout = 0

                if exc_info is not None and packet.packet_name == "disconnect":
                    exc_info = None

            if exc_info is not None:
                # Check if the exception is just a socket closed error
                # which might happen normally during disconnect
                is_normal_disconnect = False
                if isinstance(exc_info[1], (socket.error, IOError, EOFError)):
                    # Further checks might be needed depending on specific socket errors
                    # For now, assume these can happen during normal disconnects triggered elsewhere
                    if not self.connection.connected: # If disconnect was called
                        is_normal_disconnect = True

                if not is_normal_disconnect:
                    # Only raise if it's not considered part of a normal disconnect
                    exc_value, exc_tb = exc_info[1:]
                    raise exc_value.with_traceback(exc_tb)
                else:
                    # If it's a normal disconnect error, just ensure the thread stops
                    self.interrupt = True


class PacketReactor(object):
    state_name = None
    get_clientbound_packets = staticmethod(clientbound.handshake.get_packets)

    def __init__(self, connection):
        self.connection = connection
        context = self.connection.context
        self.clientbound_packets = {
            packet.get_id(context): packet
            for packet in self.__class__.get_clientbound_packets(context)}

    def read_packet(self, stream, timeout=0):
        if stream is None: # Check if file_object was closed
             return None

        try:
            ready_to_read = select.select([stream], [], [], timeout)[0]
        except ValueError: # Happens if stream is closed
             raise EOFError("Socket stream closed")


        if ready_to_read:
            length = VarInt.read(stream)

            packet_data = packets.PacketBuffer()

            read_so_far = 0
            while read_so_far < length:
                 chunk = stream.read(length - read_so_far)
                 if not chunk:
                     raise EOFError("Socket connection broken")
                 packet_data.send(chunk)
                 read_so_far += len(chunk)

            packet_data.reset_cursor()

            if self.connection.options.compression_enabled:
                decompressed_size = VarInt.read(packet_data)
                if decompressed_size > 0:
                    decompressor = zlib.decompressobj()
                    decompressed_packet = decompressor.decompress(
                                                       packet_data.read())
                    assert len(decompressed_packet) == decompressed_size, \
                        'decompressed length %d, but expected %d' % \
                        (len(decompressed_packet), decompressed_size)
                    packet_data.reset()
                    packet_data.send(decompressed_packet)
                    packet_data.reset_cursor()

            packet_id = VarInt.read(packet_data)

            if packet_id in self.clientbound_packets:
                packet = self.clientbound_packets[packet_id]()
                packet.context = self.connection.context
                packet.read(packet_data)
            else:
                packet = packets.Packet()
                packet.context = self.connection.context
                packet.id = packet_id
            return packet
        else:
            return None

    def react(self, packet):
        raise NotImplementedError("Call to base reactor")

    def handle_exception(self, exc, exc_info):
        return False


class LoginReactor(PacketReactor):
    get_clientbound_packets = staticmethod(clientbound.login.get_packets)

    def react(self, packet):
        if packet.packet_name == "encryption request":

            secret = encryption.generate_shared_secret()
            token, encrypted_secret = encryption.encrypt_token_and_secret(
                packet.public_key, packet.verify_token, secret)

            if packet.server_id != '-':
                server_id = encryption.generate_verification_hash(
                    packet.server_id, secret, packet.public_key)
                if self.connection.auth_token is not None:
                    self.connection.auth_token.join(server_id)

            encryption_response = serverbound.login.EncryptionResponsePacket()
            encryption_response.shared_secret = encrypted_secret
            encryption_response.verify_token = token

            self.connection.write_packet(encryption_response, force=True)

            cipher = encryption.create_AES_cipher(secret)
            encryptor = cipher.encryptor()
            decryptor = cipher.decryptor()

            # Ensure the original socket exists before wrapping
            if self.connection.socket is None:
                raise InvalidState("Socket is None during encryption setup.")

            self.connection.socket = encryption.EncryptedSocketWrapper(
                self.connection.socket, encryptor, decryptor)
            self.connection.file_object = \
                encryption.EncryptedFileObjectWrapper(
                    self.connection.file_object, decryptor)

        elif packet.packet_name == "disconnect":
            try:
                msg = json.loads(packet.json_data)['text']
            except (ValueError, TypeError, KeyError):
                msg = packet.json_data
            match = re.match(r"Outdated (client! Please use|server!"
                             r" I'm still on) (?P<ver>\S+)$", msg)
            if match:
                ver = match.group('ver')
                self.connection._version_mismatch(server_version=ver)
            raise LoginDisconnect('The server rejected our login attempt '
                                  'with: "%s".' % msg)

        elif packet.packet_name == "login success":
            self.connection.reactor = PlayingReactor(self.connection)

        elif packet.packet_name == "set compression":
            self.connection.options.compression_threshold = packet.threshold
            self.connection.options.compression_enabled = True

        elif packet.packet_name == "login plugin request":
            self.connection.write_packet(
                serverbound.login.PluginResponsePacket(
                    message_id=packet.message_id, successful=False))


class PlayingReactor(PacketReactor):
    get_clientbound_packets = staticmethod(clientbound.play.get_packets)

    def react(self, packet):
        if packet.packet_name == "set compression":
            self.connection.options.compression_threshold = packet.threshold
            self.connection.options.compression_enabled = True

        elif packet.packet_name == "keep alive":
            keep_alive_packet = serverbound.play.KeepAlivePacket()
            keep_alive_packet.keep_alive_id = packet.keep_alive_id
            self.connection.write_packet(keep_alive_packet)

        elif packet.packet_name == "player position and look":
            if self.connection.context.protocol_later_eq(107):
                teleport_confirm = serverbound.play.TeleportConfirmPacket()
                teleport_confirm.teleport_id = packet.teleport_id
                self.connection.write_packet(teleport_confirm)
            else:
                position_response = serverbound.play.PositionAndLookPacket()
                position_response.x = packet.x
                position_response.feet_y = packet.y
                position_response.z = packet.z
                position_response.yaw = packet.yaw
                position_response.pitch = packet.pitch
                position_response.on_ground = True
                self.connection.write_packet(position_response)
            self.connection.spawned = True

        elif packet.packet_name == "disconnect":
            self.connection.disconnect()


class StatusReactor(PacketReactor):
    get_clientbound_packets = staticmethod(clientbound.status.get_packets)

    def __init__(self, connection, do_ping=False):
        super(StatusReactor, self).__init__(connection)
        self.do_ping = do_ping

    def react(self, packet):
        if packet.packet_name == "response":
            status_dict = json.loads(packet.json_response)
            if self.do_ping:
                ping_packet = serverbound.status.PingPacket()
                ping_packet.time = int(1000 * timeit.default_timer())
                self.connection.write_packet(ping_packet)
            else:
                self.connection.disconnect()
            self.handle_status(status_dict)

        elif packet.packet_name == "ping":
            if self.do_ping:
                now = int(1000 * timeit.default_timer())
                self.connection.disconnect()
                self.handle_ping(now - packet.time)

    def handle_status(self, status_dict):
        print(status_dict)

    def handle_ping(self, latency_ms):
        print('Ping: %d ms' % latency_ms)


class PlayingStatusReactor(StatusReactor):
    def __init__(self, connection):
        super(PlayingStatusReactor, self).__init__(connection, do_ping=False)

    def handle_status(self, status):
        if status == {}:
            raise IOError('Invalid server status.')
        elif 'version' not in status or 'protocol' not in status['version']:
            return self.handle_failure()

        proto = status['version']['protocol']
        if proto not in self.connection.allowed_proto_versions:
            self.connection._version_mismatch(
                server_protocol=proto,
                server_version=status['version'].get('name'))

        self.handle_proto_version(proto)

    def handle_proto_version(self, proto_version):
        self.connection.allowed_proto_versions = {proto_version}
        self.connection.connect()

    def handle_failure(self):
        self.handle_proto_version(self.connection.default_proto_version)

    def handle_exception(self, exc, exc_info):
        if isinstance(exc, EOFError):
            self.connection.disconnect(immediate=True)
            self.handle_failure()
            return True
