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
package org.apache.ratis.quic.client;

import org.apache.ratis.client.RaftClientConfigKeys;
import org.apache.ratis.client.impl.ClientProtoUtils;
import org.apache.ratis.client.impl.RaftClientRpcWithProxy;
import org.apache.ratis.conf.RaftProperties;
import org.apache.ratis.proto.RaftProtos;
import org.apache.ratis.proto.netty.NettyProtos.RaftNettyServerReplyProto;
import org.apache.ratis.proto.netty.NettyProtos.RaftNettyServerRequestProto;
import org.apache.ratis.protocol.ClientId;
import org.apache.ratis.protocol.GroupInfoRequest;
import org.apache.ratis.protocol.GroupListRequest;
import org.apache.ratis.protocol.GroupManagementRequest;
import org.apache.ratis.protocol.LeaderElectionManagementRequest;
import org.apache.ratis.protocol.RaftClientReply;
import org.apache.ratis.protocol.RaftClientRequest;
import org.apache.ratis.protocol.RaftPeerId;
import org.apache.ratis.protocol.SetConfigurationRequest;
import org.apache.ratis.protocol.SnapshotManagementRequest;
import org.apache.ratis.protocol.TransferLeadershipRequest;
import org.apache.ratis.protocol.exceptions.TimeoutIOException;
import org.apache.ratis.quic.QuicRpcProxy;
import org.apache.ratis.util.IOUtils;
import org.apache.ratis.util.JavaUtils;
import org.apache.ratis.util.TimeDuration;
import org.apache.ratis.util.TimeoutExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * RaftClient RPC implementation over QUIC for external application clients
 * (e.g. CounterClient).
 *
 * <h3>Stream-per-RPC model</h3>
 * Each RPC call is routed through {@link QuicRpcProxy#sendAsync}, which opens
 * a brand-new short-lived QUIC stream for any request type that is not one of
 * the four persistent P2P streams (see {@link QuicRpcProxy#sendOnNewStream}).
 * This completely eliminates head-of-line blocking between concurrent client
 * calls at the QUIC layer — each RPC is independent.
 *
 * <p>Structure is intentionally kept close to {@code NettyClientRpc} so that
 * the thesis benchmarks can swap transports by changing a single factory class.
 */
public class QuicClientRpc extends RaftClientRpcWithProxy<QuicRpcProxy> {

  public static final Logger LOG = LoggerFactory.getLogger(QuicClientRpc.class);

  private final ClientId clientId;
  private final TimeDuration requestTimeout;
  private final TimeoutExecutor scheduler = TimeoutExecutor.getInstance();

  public QuicClientRpc(ClientId clientId, RaftProperties properties) {
    super(new QuicRpcProxy.PeerMap(clientId.toString(), properties));
    this.clientId       = clientId;
    this.requestTimeout = RaftClientConfigKeys.Rpc.requestTimeout(properties);
  }

  @Override
  public CompletableFuture<RaftClientReply> sendRequestAsync(
      RaftClientRequest request) {
    final RaftPeerId serverId = request.getServerId();
    final long callId = request.getCallId();
    try {
      final QuicRpcProxy proxy = getProxies().getProxy(serverId);
      final RaftNettyServerRequestProto proto = buildRequestProto(request);
      final CompletableFuture<RaftClientReply> replyFuture = new CompletableFuture<>();

      proxy.sendAsync(proto)
          .thenApply(replyProto -> toClientReply(request, replyProto))
          .whenComplete((reply, ex) -> {
            if (ex != null) {
              replyFuture.completeExceptionally(ex);
              return;
            }
            Throwable err = reply.getNotLeaderException();
            if (err == null) err = reply.getLeaderNotReadyException();
            if (err != null) replyFuture.completeExceptionally(err);
            else             replyFuture.complete(reply);
          });

      scheduler.onTimeout(requestTimeout, () -> {
        if (!replyFuture.isDone()) {
          replyFuture.completeExceptionally(new TimeoutIOException(
              clientId + "->" + serverId + " request #" + callId
                  + " timeout " + requestTimeout));
        }
      }, LOG, () -> "Timeout check for client request #" + callId);

      return replyFuture;
    } catch (Throwable e) {
      return JavaUtils.completeExceptionally(e);
    }
  }

  @Override
  public RaftClientReply sendRequest(RaftClientRequest request) throws IOException {
    try {
      return sendRequestAsync(request)
          .get(requestTimeout.getDuration(), requestTimeout.getUnit());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted waiting for QUIC reply", e);
    } catch (ExecutionException e) {
      throw IOUtils.toIOException(e);
    } catch (java.util.concurrent.TimeoutException e) {
      throw new TimeoutIOException(e.getMessage(), e);
    }
  }

  // ---- Proto building (mirrors NettyClientRpc) ----------------------------

  private static RaftNettyServerRequestProto buildRequestProto(
      RaftClientRequest request) {
    final RaftNettyServerRequestProto.Builder b =
        RaftNettyServerRequestProto.newBuilder();
    if (request instanceof GroupManagementRequest) {
      b.setGroupManagementRequest(
          ClientProtoUtils.toGroupManagementRequestProto(
              (GroupManagementRequest) request));
    } else if (request instanceof SetConfigurationRequest) {
      b.setSetConfigurationRequest(
          ClientProtoUtils.toSetConfigurationRequestProto(
              (SetConfigurationRequest) request));
    } else if (request instanceof GroupListRequest) {
      b.setGroupListRequest(
          ClientProtoUtils.toGroupListRequestProto(
              (GroupListRequest) request));
    } else if (request instanceof GroupInfoRequest) {
      b.setGroupInfoRequest(
          ClientProtoUtils.toGroupInfoRequestProto(
              (GroupInfoRequest) request));
    } else if (request instanceof TransferLeadershipRequest) {
      b.setTransferLeadershipRequest(
          ClientProtoUtils.toTransferLeadershipRequestProto(
              (TransferLeadershipRequest) request));
    } else if (request instanceof SnapshotManagementRequest) {
      b.setSnapshotManagementRequest(
          ClientProtoUtils.toSnapshotManagementRequestProto(
              (SnapshotManagementRequest) request));
    } else if (request instanceof LeaderElectionManagementRequest) {
      b.setLeaderElectionManagementRequest(
          ClientProtoUtils.toLeaderElectionManagementRequestProto(
              (LeaderElectionManagementRequest) request));
    } else {
      b.setRaftClientRequest(
          ClientProtoUtils.toRaftClientRequestProto(request));
    }
    return b.build();
  }

  private static RaftClientReply toClientReply(RaftClientRequest request,
      RaftNettyServerReplyProto replyProto) {
    if (request instanceof GroupListRequest) {
      return ClientProtoUtils.toGroupListReply(replyProto.getGroupListReply());
    } else if (request instanceof GroupInfoRequest) {
      return ClientProtoUtils.toGroupInfoReply(replyProto.getGroupInfoReply());
    } else {
      return ClientProtoUtils.toRaftClientReply(replyProto.getRaftClientReply());
    }
  }
}
