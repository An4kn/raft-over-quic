/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ratis.quic;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.protobuf.ProtobufVarint32FrameDecoder;
import io.netty.handler.codec.protobuf.ProtobufVarint32LengthFieldPrepender;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.incubator.codec.quic.QuicChannel;
import io.netty.incubator.codec.quic.QuicClientCodecBuilder;
import io.netty.incubator.codec.quic.QuicSslContext;
import io.netty.incubator.codec.quic.QuicSslContextBuilder;
import io.netty.incubator.codec.quic.QuicStreamChannel;
import io.netty.incubator.codec.quic.QuicStreamType;

import org.apache.ratis.client.RaftClientConfigKeys;
import org.apache.ratis.conf.RaftProperties;
import org.apache.ratis.proto.netty.NettyProtos.RaftNettyServerReplyProto;
import org.apache.ratis.proto.netty.NettyProtos.RaftNettyServerRequestProto;
import org.apache.ratis.protocol.RaftPeer;
import org.apache.ratis.protocol.exceptions.AlreadyClosedException;
import org.apache.ratis.proto.RaftProtos.RaftRpcRequestProto;
import org.apache.ratis.proto.RaftProtos.ReadIndexReplyProto;
import org.apache.ratis.proto.RaftProtos.ReadIndexRequestProto;
import org.apache.ratis.quic.codec.ShadedProtobufDecoder;
import org.apache.ratis.quic.codec.ShadedProtobufEncoder;
import org.apache.ratis.util.IOUtils;
import org.apache.ratis.util.NetUtils;
import org.apache.ratis.util.PeerProxyMap;
import org.apache.ratis.util.TimeDuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.apache.ratis.proto.netty.NettyProtos.RaftNettyServerReplyProto.RaftNettyServerReplyCase.EXCEPTIONREPLY;

/**
 * Client-side QUIC proxy for one remote Raft peer.
 *
 * <h3>Connection model</h3>
 * A single {@link QuicChannel} (one UDP 4-tuple) is created per peer.
 * On top of that connection the proxy opens exactly <em>four persistent
 * bidirectional streams</em>, one per Raft message type:
 * <ol>
 *   <li>Stream {@link QuicRpcService#TAG_APPEND_ENTRIES}   – log replication</li>
 *   <li>Stream {@link QuicRpcService#TAG_HEARTBEAT}        – keep-alive</li>
 *   <li>Stream {@link QuicRpcService#TAG_INSTALL_SNAPSHOT} – snapshot transfer</li>
 *   <li>Stream {@link QuicRpcService#TAG_REQUEST_VOTE}     – leader election</li>
 * </ol>
 * Keeping heartbeats on their own stream means they are never head-of-line
 * blocked behind a large AppendEntries batch — the central QUIC advantage over
 * TCP for Raft consensus.
 *
 * <h3>Framing</h3>
 * Each message is prefixed with a Protobuf varint32 length (same as
 * {@code ratis-netty}). Multiple request-reply pairs flow through each persistent
 * stream; the {@code callId} in the proto is used to route replies back to the
 * originating {@link CompletableFuture}.
 */
public class QuicRpcProxy implements Closeable {

  public static final Logger LOG = LoggerFactory.getLogger(QuicRpcProxy.class);

  // ---- PeerMap ------------------------------------------------------------

  public static class PeerMap extends PeerProxyMap<QuicRpcProxy> {

    private final EventLoopGroup group;

    public PeerMap(String name, RaftProperties properties) {
      this(name, properties,
          new NioEventLoopGroup(0,
              (java.util.concurrent.ThreadFactory) r ->
                  new Thread(r, "QuicRpcProxy-" + name + "-")));
    }

    private PeerMap(String name, RaftProperties properties, EventLoopGroup group) {
      super(name, peer -> {
        try {
          final QuicSslContext sslCtx = buildClientSslContext(properties);
          return new QuicRpcProxy(peer, properties, group, sslCtx);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw IOUtils.toInterruptedIOException(
              "Interrupted connecting to " + peer, e);
        }
      });
      this.group = group;
    }

    @Override
    public void close() {
      super.close();
      group.shutdownGracefully();
    }
  }

  // ---- Utility: extract callId from any reply proto -----------------------

  static long getCallId(RaftNettyServerReplyProto proto) {
    switch (proto.getRaftNettyServerReplyCase()) {
      case REQUESTVOTEREPLY:
        return proto.getRequestVoteReply().getServerReply().getCallId();
      case STARTLEADERELECTIONREPLY:
        return proto.getStartLeaderElectionReply().getServerReply().getCallId();
      case APPENDENTRIESREPLY:
        return proto.getAppendEntriesReply().getServerReply().getCallId();
      case INSTALLSNAPSHOTREPLY:
        return proto.getInstallSnapshotReply().getServerReply().getCallId();
      case RAFTCLIENTREPLY:
        return proto.getRaftClientReply().getRpcReply().getCallId();
      case GROUPLISTREPLY:
        return proto.getGroupListReply().getRpcReply().getCallId();
      case GROUPINFOREPLY:
        return proto.getGroupInfoReply().getRpcReply().getCallId();
      case EXCEPTIONREPLY:
        return proto.getExceptionReply().getRpcReply().getCallId();
      default:
        throw new UnsupportedOperationException(
            "Reply case not supported: " + proto.getRaftNettyServerReplyCase());
    }
  }

  // ---- Per-stream handler -------------------------------------------------

  /**
   * One instance per persistent stream. Maintains the pending-reply map for
   * requests in flight on that stream. Replies arrive asynchronously on the
   * Netty IO thread and are dispatched by {@code callId}.
   */
  class StreamHandler extends SimpleChannelInboundHandler<RaftNettyServerReplyProto> {

    private final Map<Long, CompletableFuture<RaftNettyServerReplyProto>> pending =
        new ConcurrentHashMap<>();

    @Override
    protected void channelRead0(ChannelHandlerContext ctx,
        RaftNettyServerReplyProto proto) {
      final long callId = getCallId(proto);
      final CompletableFuture<RaftNettyServerReplyProto> future =
          pending.remove(callId);
      if (future == null) {
        LOG.debug("{}: no pending request for callId={}", peer, callId);
        return;
      }
      if (proto.getRaftNettyServerReplyCase() == EXCEPTIONREPLY) {
        future.completeExceptionally(
            (IOException) org.apache.ratis.util.ProtoUtils.toObject(
                proto.getExceptionReply().getException()));
      } else {
        future.complete(proto);
      }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      LOG.warn("{}: stream exception", peer, cause);
      failAll(new IOException("Stream error to " + peer, cause));
      ctx.close();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
      failAll(new AlreadyClosedException("Stream to " + peer + " is inactive"));
      super.channelInactive(ctx);
    }

    CompletableFuture<RaftNettyServerReplyProto> send(
        QuicStreamChannel streamChannel, RaftNettyServerRequestProto request) {
      final CompletableFuture<RaftNettyServerReplyProto> future =
          new CompletableFuture<>();
      final long callId = getCallIdFromRequest(request);
      pending.put(callId, future);

      streamChannel.writeAndFlush(request).addListener(cf -> {
        if (!cf.isSuccess()) {
          if (pending.remove(callId, future)) {
            future.completeExceptionally(cf.cause());
          }
        }
      });
      return future;
    }

    private void failAll(Throwable cause) {
      if (!pending.isEmpty()) {
        pending.values().forEach(f -> f.completeExceptionally(cause));
        pending.clear();
      }
    }
  }

  // ---- Fields & construction ----------------------------------------------

  private final RaftPeer peer;
  private final TimeDuration requestTimeout;

  /** Underlying UDP channel (shared, not per-peer). */
  private final Channel udpChannel;
  /** The single QUIC logical connection to this peer. */
  private final QuicChannel quicChannel;

  // The four persistent bidirectional streams
  private final QuicStreamChannel appendEntriesStream;
  private final QuicStreamChannel heartbeatStream;
  private final QuicStreamChannel installSnapshotStream;
  private final QuicStreamChannel requestVoteStream;

  // One handler per stream (each has its own pending-reply map)
  private final StreamHandler appendEntriesHandler  = new StreamHandler();
  private final StreamHandler heartbeatHandler      = new StreamHandler();
  private final StreamHandler installSnapshotHandler = new StreamHandler();
  private final StreamHandler requestVoteHandler    = new StreamHandler();

  QuicRpcProxy(RaftPeer peer, RaftProperties properties,
      EventLoopGroup group, QuicSslContext sslCtx) throws InterruptedException {
    this.peer           = peer;
    this.requestTimeout = RaftClientConfigKeys.Rpc.requestTimeout(properties);

    // 1. Bind a local UDP socket (port 0 = ephemeral).
    final ChannelHandler clientCodec = new QuicClientCodecBuilder()
        .sslContext(sslCtx)
        .maxIdleTimeout(30_000, TimeUnit.MILLISECONDS)
        .initialMaxData(10_000_000)
        .initialMaxStreamDataBidirectionalLocal(1_000_000)
        .initialMaxStreamDataBidirectionalRemote(1_000_000)
        .initialMaxStreamsBidirectional(100)
        .build();

    this.udpChannel = new Bootstrap()
        .group(group)
        .channel(NioDatagramChannel.class)
        .handler(clientCodec)
        .bind(0)
        .sync()
        .channel();

    // 2. Establish the QUIC handshake (TLS 1.3 inside QUIC).
    final InetSocketAddress remoteAddr =
        NetUtils.createSocketAddr(peer.getAddress());

    // SSL context is embedded in the QuicClientCodecBuilder (clientCodec) above —
    // QuicChannelBootstrap in 0.0.75+ does not accept sslContext() separately.
    this.quicChannel = QuicChannel.newBootstrap(udpChannel)
        .remoteAddress(remoteAddr)
        .streamHandler(new ChannelInitializer<QuicStreamChannel>() {
          @Override
          protected void initChannel(QuicStreamChannel ch) {
            // server-initiated streams are not expected in the P2P model
            ch.close();
          }
        })
        .connect()
        .sync()
        .getNow();

    // 3. Open the four persistent bidirectional streams, one per Raft message type.
    this.appendEntriesStream  = openStream(QuicRpcService.TAG_APPEND_ENTRIES,
        appendEntriesHandler);
    this.heartbeatStream      = openStream(QuicRpcService.TAG_HEARTBEAT,
        heartbeatHandler);
    this.installSnapshotStream = openStream(QuicRpcService.TAG_INSTALL_SNAPSHOT,
        installSnapshotHandler);
    this.requestVoteStream    = openStream(QuicRpcService.TAG_REQUEST_VOTE,
        requestVoteHandler);
  }

  /**
   * Opens one persistent bidirectional QUIC stream, writes the 1-byte tag so
   * the server can identify the stream role, then configures the full pipeline.
   */
  private QuicStreamChannel openStream(byte tag, StreamHandler handler)
      throws InterruptedException {

    // TagWriter sends the role byte on channelActive then removes itself.
    final ChannelInboundHandlerAdapter tagWriter = new ChannelInboundHandlerAdapter() {
      @Override
      public void channelActive(ChannelHandlerContext ctx) {
        final ByteBuf buf = ctx.alloc().buffer(1).writeByte(tag);
        ctx.writeAndFlush(buf);
        ctx.pipeline().remove(this);
        ctx.fireChannelActive();
      }
    };

    return quicChannel.createStream(QuicStreamType.BIDIRECTIONAL,
        new ChannelInitializer<QuicStreamChannel>() {
          @Override
          protected void initChannel(QuicStreamChannel ch) {
            final ChannelPipeline p = ch.pipeline();

            // tagWriter fires before any proto traffic
            p.addLast(tagWriter);

            // Inbound: varint32 framing → shaded proto decoder → reply handler
            p.addLast(new ProtobufVarint32FrameDecoder());
            p.addLast(new ShadedProtobufDecoder<>(
                RaftNettyServerReplyProto.getDefaultInstance()));

            // Outbound: shaded proto encoder → varint32 length prepender
            p.addLast(new ProtobufVarint32LengthFieldPrepender());
            p.addLast(ShadedProtobufEncoder.INSTANCE);

            p.addLast(handler);
          }
        }).sync().getNow();
  }

  // ---- Public API ---------------------------------------------------------

  /** Selects the correct persistent stream and sends the request asynchronously. */
  public CompletableFuture<RaftNettyServerReplyProto> sendAsync(
      RaftNettyServerRequestProto proto) {
    final QuicStreamChannel stream;
    final StreamHandler handler;

    switch (proto.getRaftNettyServerRequestCase()) {
      case APPENDENTRIESREQUEST:
        // Route by content: heartbeat = empty AppendEntries
        if (proto.getAppendEntriesRequest().getEntriesCount() == 0) {
          stream  = heartbeatStream;
          handler = heartbeatHandler;
        } else {
          stream  = appendEntriesStream;
          handler = appendEntriesHandler;
        }
        break;
      case INSTALLSNAPSHOTREQUEST:
        stream  = installSnapshotStream;
        handler = installSnapshotHandler;
        break;
      case REQUESTVOTEREQUEST:
      case STARTLEADERELECTIONREQUEST:
        stream  = requestVoteStream;
        handler = requestVoteHandler;
        break;
      default:
        // All other messages (client requests, admin) go via a fresh stream.
        // This path is not used in normal P2P operation; QuicClientRpc handles
        // external client traffic on its own connection.
        return sendOnNewStream(proto);
    }
    return handler.send(stream, proto);
  }

  public RaftNettyServerReplyProto send(RaftRpcRequestProto rpcRequest,
      RaftNettyServerRequestProto proto) throws IOException {
    final CompletableFuture<RaftNettyServerReplyProto> future = sendAsync(proto);
    try {
      final TimeDuration timeout = requestTimeout.add(
          rpcRequest.getTimeoutMs(), TimeUnit.MILLISECONDS);
      return future.get(timeout.getDuration(), timeout.getUnit());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw IOUtils.toInterruptedIOException(
          org.apache.ratis.util.ProtoUtils.toString(rpcRequest)
              + " interrupted sending to " + peer, e);
    } catch (ExecutionException e) {
      throw IOUtils.toIOException(e);
    } catch (TimeoutException e) {
      throw new org.apache.ratis.protocol.exceptions.TimeoutIOException(
          e.getMessage(), e);
    }
  }

  /**
   * Sends a request on a brand-new short-lived stream (fallback for request
   * types that don't belong to the four persistent P2P streams).
   */
  private CompletableFuture<RaftNettyServerReplyProto> sendOnNewStream(
      RaftNettyServerRequestProto proto) {
    final CompletableFuture<RaftNettyServerReplyProto> result =
        new CompletableFuture<>();
    try {
      final StreamHandler ephemeralHandler = new StreamHandler();
      final QuicStreamChannel ch = openStream(QuicRpcService.TAG_CLIENT_REQUEST,
          ephemeralHandler);
      ephemeralHandler.send(ch, proto).whenComplete((reply, ex) -> {
        if (ex != null) {
          result.completeExceptionally(ex);
        } else {
          result.complete(reply);
        }
        ch.close();
      });
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      result.completeExceptionally(e);
    }
    return result;
  }

  /**
   * Sends a ReadIndex request to this peer on a short-lived stream and returns
   * a future that completes with the reply.  Used by the server's async protocol
   * to forward Linearizable Read index queries to the leader.
   */
  public CompletableFuture<ReadIndexReplyProto> readIndexAsync(
      ReadIndexRequestProto request) {
    final CompletableFuture<ReadIndexReplyProto> result = new CompletableFuture<>();
    try {
      final CompletableFuture<ReadIndexReplyProto> replyFuture = new CompletableFuture<>();
      final SimpleChannelInboundHandler<ReadIndexReplyProto> replyHandler =
          new SimpleChannelInboundHandler<ReadIndexReplyProto>() {
            @Override
            protected void channelRead0(ChannelHandlerContext ctx, ReadIndexReplyProto reply) {
              replyFuture.complete(reply);
            }
            @Override
            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
              replyFuture.completeExceptionally(cause);
              ctx.close();
            }
          };

      final ChannelInboundHandlerAdapter tagWriter = new ChannelInboundHandlerAdapter() {
        @Override
        public void channelActive(ChannelHandlerContext ctx) {
          final ByteBuf buf = ctx.alloc().buffer(1)
              .writeByte(QuicRpcService.TAG_READ_INDEX);
          ctx.writeAndFlush(buf);
          ctx.pipeline().remove(this);
          ctx.fireChannelActive();
        }
      };

      final QuicStreamChannel ch = quicChannel.createStream(
          QuicStreamType.BIDIRECTIONAL,
          new ChannelInitializer<QuicStreamChannel>() {
            @Override
            protected void initChannel(QuicStreamChannel ch) {
              final ChannelPipeline p = ch.pipeline();
              p.addLast(tagWriter);
              p.addLast(new ProtobufVarint32FrameDecoder());
              p.addLast(new ShadedProtobufDecoder<>(
                  ReadIndexReplyProto.getDefaultInstance()));
              p.addLast(new ProtobufVarint32LengthFieldPrepender());
              p.addLast(ShadedProtobufEncoder.INSTANCE);
              p.addLast(replyHandler);
            }
          }).sync().getNow();

      ch.writeAndFlush(request).addListener(cf -> {
        if (!cf.isSuccess()) {
          replyFuture.completeExceptionally(cf.cause());
        }
      });

      replyFuture.whenComplete((reply, ex) -> {
        ch.close();
        if (ex != null) {
          result.completeExceptionally(ex);
        } else {
          result.complete(reply);
        }
      });
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      result.completeExceptionally(e);
    }
    return result;
  }

  @Override
  public void close() {
    quicChannel.close();
    udpChannel.close();
  }

  // ---- Helpers ------------------------------------------------------------

  static long getCallIdFromRequest(RaftNettyServerRequestProto proto) {
    final RaftRpcRequestProto rpc;
    switch (proto.getRaftNettyServerRequestCase()) {
      case REQUESTVOTEREQUEST:
        rpc = proto.getRequestVoteRequest().getServerRequest(); break;
      case APPENDENTRIESREQUEST:
        rpc = proto.getAppendEntriesRequest().getServerRequest(); break;
      case INSTALLSNAPSHOTREQUEST:
        rpc = proto.getInstallSnapshotRequest().getServerRequest(); break;
      case STARTLEADERELECTIONREQUEST:
        rpc = proto.getStartLeaderElectionRequest().getServerRequest(); break;
      case RAFTCLIENTREQUEST:
        rpc = proto.getRaftClientRequest().getRpcRequest(); break;
      case SETCONFIGURATIONREQUEST:
        rpc = proto.getSetConfigurationRequest().getRpcRequest(); break;
      case GROUPMANAGEMENTREQUEST:
        rpc = proto.getGroupManagementRequest().getRpcRequest(); break;
      case GROUPLISTREQUEST:
        rpc = proto.getGroupListRequest().getRpcRequest(); break;
      case GROUPINFOREQUEST:
        rpc = proto.getGroupInfoRequest().getRpcRequest(); break;
      case TRANSFERLEADERSHIPREQUEST:
        rpc = proto.getTransferLeadershipRequest().getRpcRequest(); break;
      case SNAPSHOTMANAGEMENTREQUEST:
        rpc = proto.getSnapshotManagementRequest().getRpcRequest(); break;
      case LEADERELECTIONMANAGEMENTREQUEST:
        rpc = proto.getLeaderElectionManagementRequest().getRpcRequest(); break;
      default:
        throw new UnsupportedOperationException(
            "Cannot extract callId for: " + proto.getRaftNettyServerRequestCase());
    }
    return rpc.getCallId();
  }

  // ---- TLS context for outgoing connections -------------------------------

  public static QuicSslContext buildClientSslContext(RaftProperties properties) {
    final String caCert   = QuicConfigKeys.Client.tlsCaCert(properties);
    final boolean insecure = QuicConfigKeys.Client.tlsInsecure(properties);
    final QuicSslContextBuilder b = QuicSslContextBuilder.forClient()
        .applicationProtocols(QuicConfigKeys.ALPN);
    if (insecure) {
      b.trustManager(InsecureTrustManagerFactory.INSTANCE);
    } else if (caCert != null) {
      b.trustManager(new File(caCert));
    }
    // Mutual TLS (optional)
    final String cert = QuicConfigKeys.Client.tlsCert(properties);
    final String key  = QuicConfigKeys.Client.tlsKey(properties);
    if (cert != null && key != null) {
      b.keyManager(new File(key), null, new File(cert));
    }
    return b.build();
  }
}
