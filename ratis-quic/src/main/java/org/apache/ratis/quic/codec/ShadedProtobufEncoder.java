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
package org.apache.ratis.quic.codec;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageEncoder;

import org.apache.ratis.thirdparty.com.google.protobuf.MessageLite;

import java.util.List;

/**
 * Replaces Netty's built-in {@code ProtobufEncoder} for the ratis-quic module.
 *
 * The built-in encoder was compiled against the unshaded {@code com.google.protobuf.*}
 * and would fail to accept Ratis proto messages (shaded under
 * {@code org.apache.ratis.thirdparty.com.google.protobuf.*}).
 *
 * This encoder calls {@link MessageLite#toByteArray()} on the shaded message and wraps
 * the result in a zero-copy {@link Unpooled#wrappedBuffer(byte[])} ByteBuf.  The
 * downstream {@link io.netty.handler.codec.protobuf.ProtobufVarint32LengthFieldPrepender}
 * then prepends the varint32 length — the same two-handler pattern used in ratis-netty.
 *
 * The handler is stateless and therefore marked {@link ChannelHandler.Sharable};
 * use the singleton {@link #INSTANCE} instead of creating new instances per channel.
 *
 * Usage in a pipeline (identical structure to ratis-netty):
 * <pre>
 *   pipeline.addLast(new ProtobufVarint32LengthFieldPrepender());
 *   pipeline.addLast(ShadedProtobufEncoder.INSTANCE);
 * </pre>
 */
@ChannelHandler.Sharable
public final class ShadedProtobufEncoder extends MessageToMessageEncoder<MessageLite> {

  public static final ShadedProtobufEncoder INSTANCE = new ShadedProtobufEncoder();

  private ShadedProtobufEncoder() {}

  @Override
  protected void encode(ChannelHandlerContext ctx, MessageLite msg, List<Object> out) {
    out.add(Unpooled.wrappedBuffer(msg.toByteArray()));
  }
}
