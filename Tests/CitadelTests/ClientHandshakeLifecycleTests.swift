@testable import Citadel
import NIO
import NIOEmbedded
import NIOConcurrencyHelpers
import NIOSSH
import XCTest

final class ClientHandshakeLifecycleTests: XCTestCase {
    private enum TransportFailure: Error { case invalidPacket }

    func testTransportErrorAfterAuthenticationClosesChannel() throws {
        let loop = EmbeddedEventLoop()
        let handler = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        let channel = EmbeddedChannel(handler: handler, loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 22)).wait()
        channel.pipeline.fireUserInboundEventTriggered(UserAuthSuccessEvent())
        XCTAssertNoThrow(try handler.authenticated.wait())
        XCTAssertTrue(channel.isActive)
        let closeObserved = NIOLockedValueBox(false)
        channel.closeFuture.whenComplete { _ in closeObserved.withLockedValue { $0 = true } }

        channel.pipeline.fireErrorCaught(TransportFailure.invalidPacket)
        loop.run()
        XCTAssertFalse(channel.isActive, "A fatal parent error must close an authenticated client transport")
        XCTAssertTrue(closeObserved.withLockedValue { $0 }, "SSHClient disconnect observers must receive the close future")
        loop.advanceTime(by: .seconds(10))
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    func testLoginErrorFailsWaiterAndClosesChannel() throws {
        let loop = EmbeddedEventLoop()
        let handler = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        let channel = try connectedChannel(handler: handler, loop: loop)
        channel.pipeline.fireErrorCaught(TransportFailure.invalidPacket)
        XCTAssertFalse(channel.isActive)
        guard case .failure(let error)? = result(of: handler) else {
            return XCTFail("Login error must finish the authentication waiter")
        }
        XCTAssertTrue(error is TransportFailure)
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    func testTimeoutFailsWaiterAndClosesChannel() throws {
        let loop = EmbeddedEventLoop()
        let handler = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        let channel = try connectedChannel(handler: handler, loop: loop)
        loop.advanceTime(by: .seconds(10))
        XCTAssertFalse(channel.isActive)
        guard case .failure(let error)? = result(of: handler) else {
            return XCTFail("Login timeout must finish the authentication waiter")
        }
        XCTAssertEqual(error as? ChannelError, .connectTimeout(.seconds(10)))
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    func testEarlyCloseFinishesWaiterEvenWhenInactiveIsConsumed() throws {
        let loop = EmbeddedEventLoop()
        let handler = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        let channel = EmbeddedChannel(loop: loop)
        try channel.pipeline.addHandlers(InactiveConsumer(), handler).wait()
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 22)).wait()
        try channel.close().wait()
        loop.run()
        guard case .failure? = result(of: handler) else {
            return XCTFail("Parent close must finish the waiter without relying on channelInactive forwarding")
        }
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    func testSuccessfulAuthenticationCancelsTimeout() throws {
        let loop = EmbeddedEventLoop()
        let handler = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        let channel = try connectedChannel(handler: handler, loop: loop)
        channel.pipeline.fireUserInboundEventTriggered(UserAuthSuccessEvent())
        loop.advanceTime(by: .seconds(20))
        XCTAssertTrue(channel.isActive, "An authenticated session must survive its former login deadline")
        guard case .success? = result(of: handler) else {
            return XCTFail("Authentication must remain successful")
        }
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    func testRemovingWaitingHandlerClosesChannelAndReleasesTimer() throws {
        let loop = EmbeddedEventLoop()
        var handler: ClientHandshakeHandler? = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        weak var weakHandler = handler
        let channel = try connectedChannel(handler: try XCTUnwrap(handler), loop: loop)
        try channel.pipeline.removeHandler(try XCTUnwrap(handler)).wait()
        XCTAssertFalse(channel.isActive)
        guard case .failure? = result(of: try XCTUnwrap(handler)) else {
            return XCTFail("Removing the waiting handler must finish its waiter")
        }
        handler = nil
        XCTAssertNil(weakHandler, "A canceled deadline must not retain the removed handler")
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    func testRemovingAuthenticatedHandlerKeepsChannelAndReleasesTimer() throws {
        let loop = EmbeddedEventLoop()
        var handler: ClientHandshakeHandler? = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        weak var weakHandler = handler
        let channel = try connectedChannel(handler: try XCTUnwrap(handler), loop: loop)
        channel.pipeline.fireUserInboundEventTriggered(UserAuthSuccessEvent())
        try channel.pipeline.removeHandler(try XCTUnwrap(handler)).wait()
        handler = nil
        XCTAssertNil(weakHandler)
        loop.advanceTime(by: .seconds(20))
        XCTAssertTrue(channel.isActive, "Removing a completed observer must preserve the established channel")
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    func testReinsertingCompletedObserverDoesNotRestartLoginTimeout() throws {
        let loop = EmbeddedEventLoop()
        let handler = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        let channel = try connectedChannel(handler: handler, loop: loop)
        channel.pipeline.fireUserInboundEventTriggered(UserAuthSuccessEvent())
        try channel.pipeline.removeHandler(handler).wait()
        try channel.pipeline.addHandler(handler).wait()
        loop.advanceTime(by: .seconds(20))
        XCTAssertTrue(channel.isActive, "A completed handshake deadline must not be resurrected")
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    private func connectedChannel(handler: ClientHandshakeHandler, loop: EmbeddedEventLoop) throws -> EmbeddedChannel {
        let channel = EmbeddedChannel(handler: handler, loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 22)).wait()
        return channel
    }

    private func result(of handler: ClientHandshakeHandler) -> Result<Void, Error>? {
        let captured = NIOLockedValueBox<Result<Void, Error>?>(nil)
        handler.authenticated.whenComplete { outcome in
            captured.withLockedValue { $0 = outcome }
        }
        return captured.withLockedValue { $0 }
    }
}

/// Matches NIOSSHHandler's parent-channel behavior without involving a network peer.
private final class InactiveConsumer: ChannelInboundHandler, Sendable {
    typealias InboundIn = Any
    func channelInactive(context: ChannelHandlerContext) {}
}
