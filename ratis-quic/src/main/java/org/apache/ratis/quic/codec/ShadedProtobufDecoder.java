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

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageDecoder;

import org.apache.ratis.thirdparty.com.google.protobuf.MessageLite;
import org.apache.ratis.thirdparty.com.google.protobuf.Parser;

import java.util.List;

/**
 * Replaces Netty's built-in {@code ProtobufDecoder} for the ratis-quic module.
 *
 * The built-in decoder was compiled against the unshaded {@code com.google.protobuf.*}
 * and would throw a ClassCastException at runtime because Ratis proto classes extend
 * {@code org.apache.ratis.thirdparty.com.google.protobuf.GeneratedMessageV3}.
 *
 * This decoder receives a fully-assembled {@link ByteBuf} frame from the upstream
 * {@link io.netty.handler.codec.protobuf.ProtobufVarint32FrameDecoder} (which is safe
 * because it only touches ByteBuf, never Protobuf classes), copies the bytes into a
 * plain {@code byte[]}, and delegates to the shaded {@link Parser#parseFrom(byte[])}.
 *
 * Usage in a pipeline (identical structure to ratis-netty):
 * <pre>
 *   pipeline.addLast(new ProtobufVarint32FrameDecoder());
 *   pipeline.addLast(new ShadedProtobufDecoder&lt;&gt;(RaftNettyServerRequestProto.getDefaultInstance()));
 * </pre>
 *
 * @param <M> the concrete shaded Protobuf message type to decode into
 */
public final class ShadedProtobufDecoder<M extends MessageLite>
    extends MessageToMessageDecoder<ByteBuf> {

  private final Parser<M> parser;

  /**
   * @param defaultInstance prototype used only to obtain the {@link Parser};
   *                        e.g. {@code RaftNettyServerRequestProto.getDefaultInstance()}
   */
  @SuppressWarnings("unchecked")
  public ShadedProtobufDecoder(M defaultInstance) {
    this.parser = (Parser<M>) defaultInstance.getParserForType();
  }

  @Override
  protected void decode(ChannelHandlerContext ctx, ByteBuf msg, List<Object> out)
      throws Exception {
    final byte[] bytes = new byte[msg.readableBytes()];
    msg.readBytes(bytes);
    out.add(parser.parseFrom(bytes));
  }
}
